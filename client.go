package sshcommands

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// buildAuthMethods returns the SSH auth methods configured in opts
// (private key file, optionally passphrase-protected, and/or password).
func buildAuthMethods(opts *Opts, log Logger) ([]ssh.AuthMethod, error) {
	var auth []ssh.AuthMethod
	if opts.KeyFile != "" {
		signer, err := loadPrivateKey(filepath.FromSlash(opts.KeyFile), opts.KeyPassphrase, log)
		if err != nil {
			return nil, err
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if opts.Password != "" {
		auth = append(auth, ssh.Password(opts.Password))
	}
	if len(auth) == 0 {
		return nil, errors.New("no SSH auth: set KeyFile or Password in Opts")
	}
	return auth, nil
}

// loadPrivateKey reads and parses the private key at p. On Unix a warning is
// logged when the file is readable by group or others.
func loadPrivateKey(p, passphrase string, log Logger) (ssh.Signer, error) {
	if fi, err := os.Stat(p); err == nil && !isWindows && fi.Mode().Perm()&0o077 != 0 && log != nil {
		log.Warn("private key file %q is accessible by group/others (mode %04o); use chmod 600",
			filepath.Base(p), fi.Mode().Perm())
	}
	key, err := readLimited(p, maxPrivateKeySize)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	if passphrase != "" {
		signer, err := ssh.ParsePrivateKeyWithPassphrase(key, []byte(passphrase))
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		return signer, nil
	}
	signer, err := ssh.ParsePrivateKey(key)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		return nil, errors.New("private key is encrypted: set KeyPassphrase in Opts")
	}
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return signer, nil
}

// dialSSH opens a TCP connection and performs the SSH handshake. The deadline
// opts.sshTimeout() covers connect and handshake; it is still set on the
// returned conn so the caller can finish further setup (e.g. SFTP start)
// before calling finishSetup.
func dialSSH(opts *Opts, hostKeyCB ssh.HostKeyCallback, auth []ssh.AuthMethod) (*ssh.Client, net.Conn, error) {
	timeout := opts.sshTimeout()
	addr := opts.addr()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		closeQuietly(conn)
		return nil, nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            opts.User,
		Auth:            auth,
		HostKeyCallback: hostKeyCB,
		Timeout:         timeout,
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		closeQuietly(conn)
		return nil, nil, err
	}
	return ssh.NewClient(c, chans, reqs), conn, nil
}

// finishSetup removes the setup deadline (so long transfers are not cut off)
// and starts the keepalive that detects a hanging server instead.
func finishSetup(opts *Opts, client *ssh.Client, conn net.Conn, log Logger) error {
	if err := conn.SetDeadline(time.Time{}); err != nil {
		closeQuietly(client)
		return err
	}
	if interval := opts.keepAliveInterval(); interval > 0 {
		go keepAlive(client, interval, opts.keepAliveMaxMissed(), log)
	}
	return nil
}

// keepAlive sends "keepalive@openssh.com" requests every interval and closes
// the client after maxMissed unanswered requests, which unblocks all pending
// SFTP calls with an error. It returns when the connection is closed.
func keepAlive(client *ssh.Client, interval time.Duration, maxMissed int, log Logger) {
	done := make(chan struct{})
	go func() {
		_ = client.Wait()
		close(done)
	}()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	missed := 0
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
		}
		reply := make(chan error, 1)
		go func() {
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			reply <- err
		}()
		select {
		case <-done:
			return
		case err := <-reply:
			if err != nil {
				closeQuietly(client)
				return
			}
			missed = 0
		case <-time.After(interval):
			missed++
			if missed >= maxMissed {
				if log != nil {
					log.Warn("SSH server did not answer %d keepalive requests; closing connection", missed)
				}
				closeQuietly(client)
				return
			}
		}
	}
}

// dial validates opts and connects with host key verification via opts.HostKey.
// The setup deadline is still active on the returned conn.
func dial(opts *Opts, log Logger) (*ssh.Client, net.Conn, error) {
	if err := opts.validate(); err != nil {
		return nil, nil, err
	}
	hostKeyCB, err := hostKeyCallback(opts.HostKey, log)
	if err != nil {
		return nil, nil, err
	}
	auth, err := buildAuthMethods(opts, log)
	if err != nil {
		return nil, nil, err
	}
	return dialSSH(opts, hostKeyCB, auth)
}

// NewSFTPClient returns an SFTP client; caller must Close() both clients.
func NewSFTPClient(opts *Opts, log Logger) (*sftp.Client, *ssh.Client, error) {
	client, conn, err := dial(opts, log)
	if err != nil {
		return nil, nil, fmt.Errorf("connect %s: %w", opts.addr(), err)
	}
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		closeQuietly(client)
		return nil, nil, fmt.Errorf("sftp: %w", err)
	}
	if err := finishSetup(opts, client, conn, log); err != nil {
		closeQuietly(sftpClient)
		return nil, nil, err
	}
	return sftpClient, client, nil
}

// DialWithHostKeyCallback connects using a custom host key callback instead of
// opts.HostKey. opts.HostKey is ignored.
func DialWithHostKeyCallback(opts *Opts, hostKeyCallback ssh.HostKeyCallback, log Logger) (*ssh.Client, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	if hostKeyCallback == nil {
		return nil, errors.New("host key callback required")
	}
	auth, err := buildAuthMethods(opts, log)
	if err != nil {
		return nil, err
	}
	client, conn, err := dialSSH(opts, hostKeyCallback, auth)
	if err != nil {
		return nil, err
	}
	if err := finishSetup(opts, client, conn, log); err != nil {
		return nil, err
	}
	if log != nil {
		log.Info("SSH connection established: %s", opts.addr())
	}
	return client, nil
}
