package sshcommands

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// FormatKnownHostsHostToken returns the host token for a known_hosts entry.
func FormatKnownHostsHostToken(host string, port int) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if port > 0 && port != DefaultSSHPort {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return host
}

// hostTokenPattern allows exactly one concrete host: "host", "[host]:port"
// or a hashed token "|1|salt|hash". Wildcards (*, ?), negation (!), lists
// (,), markers (@) and whitespace are rejected.
var hostTokenPattern = regexp.MustCompile(`^(\[[A-Za-z0-9._:%-]+\]:[0-9]{1,5}|[A-Za-z0-9._:%-]+|\|1\|[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]+)$`)

// normalizeKnownHostsEntry validates a host token and key line and returns the
// key re-serialized as "key-type base64" (options and comments are dropped).
func normalizeKnownHostsEntry(hostToken, keyLine string) (string, string, error) {
	hostToken = strings.TrimSpace(hostToken)
	keyLine = strings.TrimSpace(keyLine)
	if hostToken == "" {
		return "", "", errors.New("known_hosts host token is empty")
	}
	if keyLine == "" {
		return "", "", errors.New("known_hosts key line is empty")
	}
	if strings.ContainsAny(hostToken+keyLine, "\r\n\x00") {
		return "", "", errors.New("known_hosts entry must not contain line breaks or NUL")
	}
	if !hostTokenPattern.MatchString(hostToken) {
		return "", "", fmt.Errorf("known_hosts host token %q invalid: expected host, [host]:port or hashed token", hostToken)
	}
	pub, _, options, _, err := ssh.ParseAuthorizedKey([]byte(keyLine))
	if err != nil {
		return "", "", fmt.Errorf("known_hosts key line invalid: %w", err)
	}
	if len(options) > 0 {
		return "", "", errors.New("known_hosts key line must not contain options")
	}
	return hostToken, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), nil
}

// AppendKnownHostsLine appends a host token and key line to a known_hosts file.
// The token must name exactly one host (see FormatKnownHostsHostToken); the key
// is written as "key-type base64". Parent directories are created as needed.
// A missing newline at the end of the existing file is added first.
func AppendKnownHostsLine(knownHostsPath, hostToken, keyLine string, log Logger) (err error) {
	hostToken, keyLine, err = normalizeKnownHostsEntry(hostToken, keyLine)
	if err != nil {
		return err
	}
	path := filepath.FromSlash(strings.TrimSpace(knownHostsPath))
	if path == "" {
		return errors.New("known_hosts path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create known_hosts directory: %w", err)
	}
	needNewline, err := missingTrailingNewline(path)
	if err != nil {
		return fmt.Errorf("read known_hosts file: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600) // #nosec G304
	if err != nil {
		return fmt.Errorf("open known_hosts file: %w", err)
	}
	defer closeChecked(f, &err)
	entry := hostToken + " " + keyLine + "\n"
	if needNewline {
		entry = "\n" + entry
	}
	if _, err := f.WriteString(entry); err != nil {
		return fmt.Errorf("write known_hosts file: %w", err)
	}
	if log != nil {
		log.Info("SSH host key appended to known_hosts: %q", filepath.Base(path))
	}
	return nil
}

// missingTrailingNewline reports whether the file at p is non-empty and does
// not end with "\n". A missing file counts as not needing a newline.
func missingTrailingNewline(p string) (bool, error) {
	f, err := os.Open(p) // #nosec G304
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	defer closeQuietly(f)
	fi, err := f.Stat()
	if err != nil || fi.Size() == 0 {
		return false, err
	}
	last := make([]byte, 1)
	if _, err := f.ReadAt(last, fi.Size()-1); err != nil && err != io.EOF {
		return false, err
	}
	return last[0] != '\n', nil
}

// staticAddr is a net.Addr for known_hosts lookups without a real connection.
type staticAddr string

func (a staticAddr) Network() string { return "tcp" }
func (a staticAddr) String() string  { return string(a) }

// knownHostsKnowsHost reports whether the known_hosts file at p contains at
// least one key for host:port. A missing file knows no host.
func knownHostsKnowsHost(p, host string, port int) (bool, error) {
	if _, err := os.Stat(p); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if err := checkFileSize(p, maxKnownHostsSize); err != nil {
		return false, err
	}
	cb, err := knownhosts.New(p)
	if err != nil {
		return false, fmt.Errorf("known_hosts file invalid: %w", err)
	}
	// Probe with a key that cannot be in the file: a KeyError with Want
	// entries means the host is known (with other keys).
	probe, err := ssh.NewPublicKey(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)))
	if err != nil {
		return false, err
	}
	addr := net.JoinHostPort(strings.TrimSpace(host), strconv.Itoa(port))
	err = cb(addr, staticAddr(addr), probe)
	var ke *knownhosts.KeyError
	switch {
	case err == nil:
		return true, nil
	case errors.As(err, &ke):
		return len(ke.Want) > 0, nil
	default:
		return false, err
	}
}

// AppendServerHostKey fetches the server host key (without sending
// credentials) and appends it to knownHostsPath when the file does not know
// the host yet. A host that is already listed (with any key) is left
// unchanged and not contacted; a changed key then fails at connect time as a
// mismatch. Returns written=true when a new line was added.
func AppendServerHostKey(opts *Opts, knownHostsPath string, log Logger) (written bool, err error) {
	if err := opts.validateAddr(); err != nil {
		return false, err
	}
	path := filepath.FromSlash(strings.TrimSpace(knownHostsPath))
	known, err := knownHostsKnowsHost(path, opts.Host, opts.port())
	if err != nil {
		return false, err
	}
	if known {
		return false, nil
	}
	keyLine, err := FetchServerHostKey(opts)
	if err != nil {
		return false, err
	}
	hostToken := FormatKnownHostsHostToken(opts.Host, opts.port())
	if err := AppendKnownHostsLine(path, hostToken, keyLine, log); err != nil {
		return false, err
	}
	return true, nil
}
