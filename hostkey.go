package sshcommands

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// errHostKeyCaptured aborts the handshake in FetchServerHostKey right after
// the server key was received, before any authentication is attempted.
var errHostKeyCaptured = errors.New("host key captured")

// windowsAbsPath matches "C:\..." or "C:/...".
var windowsAbsPath = regexp.MustCompile(`^[A-Za-z]:[\\/]`)

// looksLikePath reports whether a HostKey value is meant as a file path rather
// than inline key material (key lines always contain whitespace).
func looksLikePath(s string) bool {
	if !strings.ContainsAny(s, " \t\r\n") {
		return true
	}
	return windowsAbsPath.MatchString(s) || strings.HasPrefix(s, "/") ||
		strings.HasPrefix(s, "~") || strings.HasPrefix(s, ".") || strings.HasPrefix(s, `\\`)
}

// parseHostKeyLine parses one inline host key entry: "key-type base64 [comment]"
// or a known_hosts line "host key-type base64 [comment]". Markers are rejected.
func parseHostKeyLine(line string) (ssh.PublicKey, error) {
	if pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line)); err == nil {
		return pub, nil
	}
	marker, _, pub, _, _, err := ssh.ParseKnownHosts([]byte(line))
	if err != nil {
		return nil, errors.New(`expected "key-type base64 [comment]" or a known_hosts line`)
	}
	if marker != "" {
		return nil, fmt.Errorf("marker @%s is not supported for inline host keys", marker)
	}
	return pub, nil
}

// parseInlineHostKeys parses inline host keys separated by "||" and/or newlines.
// Empty lines and lines starting with "#" are skipped; any other unparsable
// line is an error naming that line.
func parseInlineHostKeys(s string) ([]ssh.PublicKey, error) {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	var keys []ssh.PublicKey
	entry := 0
	for _, block := range strings.Split(s, "||") {
		for _, line := range strings.Split(block, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			entry++
			pub, err := parseHostKeyLine(line)
			if err != nil {
				return nil, fmt.Errorf("host key entry %d (%q): %w", entry, shorten(line, 40), err)
			}
			keys = append(keys, pub)
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("host key invalid: no key found")
	}
	return keys, nil
}

// shorten truncates s to at most n runes for error messages.
func shorten(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// logHostKeyFailure wraps cb so that verification failures are logged with the
// server key's SHA-256 fingerprint (never the full key) and the real cause.
func logHostKeyFailure(cb ssh.HostKeyCallback, log Logger) ssh.HostKeyCallback {
	if log == nil {
		return cb
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := cb(hostname, remote, key)
		if err != nil {
			log.Warn("host key verification failed for %q (server key fingerprint %s): %v",
				hostname, ssh.FingerprintSHA256(key), err)
		}
		return err
	}
}

// hostKeyCallback builds the verification callback for Opts.HostKey: either a
// known_hosts file path or inline keys (see parseInlineHostKeys).
func hostKeyCallback(hostKey string, log Logger) (ssh.HostKeyCallback, error) {
	s := strings.TrimSpace(hostKey)
	if s == "" {
		return nil, errors.New("host key required: set HostKey in Opts")
	}
	p := filepath.FromSlash(s)
	if fi, err := os.Stat(p); err == nil {
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("host key file %s is not a regular file", p)
		}
		if err := checkFileSize(p, maxKnownHostsSize); err != nil {
			return nil, fmt.Errorf("host key file: %w", err)
		}
		cb, err := knownhosts.New(p)
		if err != nil {
			return nil, fmt.Errorf("host key file: %w", err)
		}
		return logHostKeyFailure(cb, log), nil
	}
	allowed, err := parseInlineHostKeys(s)
	if err != nil {
		if looksLikePath(s) {
			return nil, fmt.Errorf("host key file not found: %s", p)
		}
		return nil, err
	}
	cb := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		got := key.Marshal()
		for _, a := range allowed {
			if bytes.Equal(got, a.Marshal()) {
				return nil
			}
		}
		return errors.New("host key mismatch: server key is not in Opts.HostKey")
	}
	return logHostKeyFailure(cb, log), nil
}

// FetchServerHostKey connects to the SSH server, captures its host key and
// returns it as a single line ("key-type base64"). The handshake is aborted
// right after the key exchange, so no credentials are sent and Opts.User,
// KeyFile and Password are not needed. The key is NOT verified; use it only
// for initial setup (trust on first use).
func FetchServerHostKey(opts *Opts) (keyLine string, err error) {
	if err := opts.validateAddr(); err != nil {
		return "", err
	}
	var captured ssh.PublicKey
	cb := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		captured = key
		return errHostKeyCaptured
	}
	client, _, err := dialSSH(opts, cb, nil)
	if err == nil {
		closeQuietly(client)
		return "", errors.New("unexpected: handshake completed without host key capture")
	}
	if !errors.Is(err, errHostKeyCaptured) {
		return "", err
	}
	if captured == nil {
		return "", errors.New("server did not send a host key")
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(captured))), nil
}

// HostKeyAlreadyPresent returns true if newKeyLine is already among the keys in
// currentValue (inline " || "-separated keys or path to a known_hosts file).
// The check ignores host names; revoked (@revoked) and @cert-authority lines
// never count as present. Use a host-aware check for known_hosts files where
// the host matters (AppendServerHostKey does).
func HostKeyAlreadyPresent(currentValue, newKeyLine string) (bool, error) {
	newKeyLine = strings.TrimSpace(newKeyLine)
	if newKeyLine == "" {
		return false, nil
	}
	newPub, err := parseHostKeyLine(newKeyLine)
	if err != nil {
		return false, nil
	}
	want := newPub.Marshal()
	currentValue = strings.TrimSpace(currentValue)
	if currentValue == "" {
		return false, nil
	}
	p := filepath.FromSlash(currentValue)
	if fi, statErr := os.Stat(p); statErr == nil && fi.Mode().IsRegular() {
		return knownHostsFileHasKey(p, want)
	}
	keys, err := parseInlineHostKeys(currentValue)
	if err != nil {
		return false, err
	}
	for _, k := range keys {
		if bytes.Equal(k.Marshal(), want) {
			return true, nil
		}
	}
	return false, nil
}

// knownHostsFileHasKey reports whether a known_hosts file contains want as a
// regular (non-revoked, non-CA) host key for any host.
func knownHostsFileHasKey(p string, want []byte) (bool, error) {
	content, err := readLimited(p, maxKnownHostsSize)
	if err != nil {
		return false, err
	}
	found := false
	for _, line := range strings.Split(string(content), "\n") {
		marker, _, pub, _, _, err := ssh.ParseKnownHosts([]byte(line))
		if err != nil || !bytes.Equal(pub.Marshal(), want) {
			continue // comments, blank or malformed lines, other keys
		}
		switch marker {
		case "revoked":
			return false, nil // a revoked key is never trusted
		case "":
			found = true
		}
	}
	return found, nil
}
