package sshcommands

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// isKnownHostsKeyMismatch reports whether err is a known_hosts key mismatch
// (host known, but with a different key).
func isKnownHostsKeyMismatch(err error) bool {
	var ke *knownhosts.KeyError
	return errors.As(err, &ke) && len(ke.Want) > 0
}

// DialKnownHosts connects using KnownHostsOptions.Path for host key verification.
// opts.HostKey is ignored. When FetchHostKey is set and the file is missing or
// does not know the host yet, the server key is fetched (without sending
// credentials) and appended. With TrustOnMismatch a changed key replaces the
// host's previous entries (development only, see KnownHostsOptions).
func DialKnownHosts(opts *Opts, kh KnownHostsOptions, log Logger) (*ssh.Client, error) {
	path := filepath.FromSlash(strings.TrimSpace(kh.Path))
	if path == "" {
		return nil, errors.New("known_hosts path required")
	}
	if err := opts.validate(); err != nil {
		return nil, err
	}

	if kh.FetchHostKey {
		if _, err := AppendServerHostKey(opts, path, log); err != nil {
			return nil, fmt.Errorf("fetch host key: %w", err)
		}
	} else if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("known_hosts file not found: %s (enable FetchHostKey to create it)", filepath.Base(path))
		}
		return nil, fmt.Errorf("known_hosts file: %w", err)
	}

	// presented holds the key the server sent in the last attempt, so a
	// trusted replacement is the key of the verified-failing connection
	// itself and not one fetched over a second connection.
	var presented ssh.PublicKey
	connect := func() (*ssh.Client, error) {
		if err := checkFileSize(path, maxKnownHostsSize); err != nil {
			return nil, fmt.Errorf("known_hosts file: %w", err)
		}
		cb, err := knownhosts.New(path)
		if err != nil {
			return nil, fmt.Errorf("known_hosts file invalid: %w", err)
		}
		if log != nil {
			log.Info("SSH host key verification enabled: %q", filepath.Base(path))
		}
		capture := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			presented = key
			return cb(hostname, remote, key)
		}
		return DialWithHostKeyCallback(opts, logHostKeyFailure(capture, log), log)
	}

	client, err := connect()
	if err == nil {
		return client, nil
	}
	if !kh.TrustOnMismatch || !isKnownHostsKeyMismatch(err) || presented == nil {
		return nil, err
	}

	keyLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(presented)))
	if log != nil {
		log.Warn("SSH host key of %q changed; TrustOnMismatch replaces its known_hosts entries with key fingerprint %s",
			opts.Host, ssh.FingerprintSHA256(presented))
	}
	if err := replaceKnownHostsEntries(path, opts.Host, opts.port(), keyLine); err != nil {
		return nil, fmt.Errorf("host key mismatch and replace failed: %w", err)
	}
	return connect()
}
