package sshcommands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func isKnownHostsKeyMismatch(err error) bool {
	return err != nil && strings.Contains(err.Error(), "knownhosts: key mismatch")
}

func buildAuthMethods(opts *Opts) ([]ssh.AuthMethod, error) {
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
	return auth, nil
}

// DialWithHostKeyCallback connects using a custom host key callback instead of
// opts.HostKey. opts.HostKey is ignored.
func DialWithHostKeyCallback(opts *Opts, hostKeyCallback ssh.HostKeyCallback, log Logger) (*ssh.Client, error) {
	if opts.Host == "" {
		return nil, fmt.Errorf("remote not configured: set Host in Opts")
	}
	auth, err := buildAuthMethods(opts)
	if err != nil {
		return nil, err
	}
	port := opts.Port
	if port <= 0 {
		port = 22
	}
	addr := fmt.Sprintf("%s:%d", opts.Host, port)
	cfg := &ssh.ClientConfig{
		User:            opts.User,
		Auth:            auth,
		HostKeyCallback: hostKeyCallback,
		Timeout:         30 * time.Second,
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	if log != nil {
		log.Info("SSH connection established: %s", addr)
	}
	return client, nil
}

// DialKnownHosts connects using KnownHostsOptions.Path for host key verification.
// opts.HostKey is ignored. When FetchHostKey is set, the server key is fetched and
// appended when the file is missing or does not contain that key yet.
func DialKnownHosts(opts *Opts, kh KnownHostsOptions, log Logger) (*ssh.Client, error) {
	path := filepath.FromSlash(strings.TrimSpace(kh.Path))
	if path == "" {
		return nil, fmt.Errorf("known_hosts path required")
	}

	if kh.FetchHostKey {
		if _, err := AppendServerHostKey(opts, path, log); err != nil {
			return nil, fmt.Errorf("fetch host key: %w", err)
		}
	} else if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("known_hosts file not found: %s (enable FetchHostKey to create it)", path)
		}
		return nil, fmt.Errorf("known_hosts file: %w", err)
	}

	connect := func() (*ssh.Client, error) {
		cb, err := knownhosts.New(path)
		if err != nil {
			return nil, fmt.Errorf("known_hosts file invalid: %w", err)
		}
		if log != nil {
			log.Info("SSH host key verification enabled: %s", path)
		}
		return DialWithHostKeyCallback(opts, cb, nil)
	}

	client, err := connect()
	if err == nil {
		return client, nil
	}
	if !kh.TrustOnMismatch || !isKnownHostsKeyMismatch(err) {
		return nil, err
	}

	if log != nil {
		log.Warn("SSH host key mismatch detected; fetching current server key")
	}
	keyLine, fetchErr := FetchServerHostKey(opts)
	if fetchErr != nil {
		return nil, fmt.Errorf("host key mismatch and fetch failed: %w", fetchErr)
	}
	port := opts.Port
	if port <= 0 {
		port = 22
	}
	hostToken := FormatKnownHostsHostToken(opts.Host, port)
	if appendErr := AppendKnownHostsLine(path, hostToken, keyLine, log); appendErr != nil {
		return nil, fmt.Errorf("host key mismatch and append failed: %w", appendErr)
	}
	return connect()
}
