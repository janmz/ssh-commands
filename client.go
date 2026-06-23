package sshcommands

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func hostKeyCallback(hostKey string, log Logger) (ssh.HostKeyCallback, error) {
	wrap := func(inner ssh.HostKeyCallback) ssh.HostKeyCallback {
		if log == nil {
			return inner
		}
		return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			err := inner(hostname, remote, key)
			if err != nil {
				line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
				log.Info("host key mismatch: server %s sent key (add to host key): %s", hostname, line)
			}
			return err
		}
	}
	s := strings.TrimSpace(hostKey)
	if s == "" {
		return nil, fmt.Errorf("host key required: set HostKey in Opts")
	}
	path := filepath.FromSlash(s)
	if fi, err := os.Stat(path); err == nil && fi.Mode().IsRegular() {
		cb, err := knownhosts.New(path)
		if err != nil {
			return nil, fmt.Errorf("host key file: %w", err)
		}
		return wrap(cb), nil
	}
	keyBlocks := strings.Split(s, "||")
	var allowedKeys []ssh.PublicKey
	for _, block := range keyBlocks {
		block = strings.ReplaceAll(block, "\r\n", "\n")
		block = strings.ReplaceAll(block, "\r", "\n")
		for _, line := range strings.Split(block, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) < 2 {
				continue
			}
			keyLine := strings.Join(parts[len(parts)-2:], " ")
			pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keyLine))
			if err != nil {
				continue
			}
			allowedKeys = append(allowedKeys, pubKey)
		}
	}
	if len(allowedKeys) > 0 {
		cb := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			for _, allowed := range allowedKeys {
				if bytes.Equal(key.Marshal(), allowed.Marshal()) {
					return nil
				}
			}
			return fmt.Errorf("host key mismatch")
		}
		return wrap(cb), nil
	}
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	parts := strings.Fields(s)
	if len(parts) < 2 {
		return nil, fmt.Errorf("host key invalid: need key-type base64")
	}
	keyLine := strings.Join(parts[len(parts)-2:], " ")
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keyLine))
	if err != nil {
		return nil, fmt.Errorf("host key parse: %w", err)
	}
	return wrap(ssh.FixedHostKey(pubKey)), nil
}

// dial establishes an SSH client from Opts. Caller must Close() it.
func dial(opts *Opts, log Logger) (*ssh.Client, error) {
	hostKeyCB, err := hostKeyCallback(opts.HostKey, log)
	if err != nil {
		return nil, err
	}
	var auth []ssh.AuthMethod
	if opts.KeyFile != "" {
		keyPath := filepath.FromSlash(opts.KeyFile)
		key, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("read key file: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if opts.Password != "" {
		auth = append(auth, ssh.Password(opts.Password))
	}
	if len(auth) == 0 {
		return nil, fmt.Errorf("no SSH auth: set KeyFile or Password in Opts")
	}
	port := opts.Port
	if port <= 0 {
		port = 22
	}
	addr := fmt.Sprintf("%s:%d", opts.Host, port)
	cfg := &ssh.ClientConfig{
		User:            opts.User,
		Auth:            auth,
		HostKeyCallback: hostKeyCB,
	}
	return ssh.Dial("tcp", addr, cfg)
}

// NewSFTPClient returns an SFTP client; caller must call Close().
func NewSFTPClient(opts *Opts, log Logger) (*sftp.Client, *ssh.Client, error) {
	client, err := dial(opts, log)
	if err != nil {
		return nil, nil, fmt.Errorf("ssh: %w", err)
	}
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		client.Close()
		return nil, nil, fmt.Errorf("sftp: %w", err)
	}
	return sftpClient, client, nil
}
