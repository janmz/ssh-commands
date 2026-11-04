// Package sshcommands provides SSH/SFTP operations (upload, list, delete,
// download, fetch host key) with parameter-based API, no config dependency.
package sshcommands

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// DefaultSSHTimeout is used when Opts.Timeout is zero.
const DefaultSSHTimeout = 30 * time.Second

// DefaultSSHPort is used when Opts.Port is zero.
const DefaultSSHPort = 22

// Keepalive defaults: a request every DefaultKeepAliveInterval; the connection
// is closed after DefaultKeepAliveMaxMissed unanswered requests.
const (
	DefaultKeepAliveInterval  = 15 * time.Second
	DefaultKeepAliveMaxMissed = 3
)

// ErrRemoteNotConfigured is returned by all operations when Opts.Host is empty.
// Callers that treat the remote as optional can check it with errors.Is.
var ErrRemoteNotConfigured = errors.New("remote not configured: set Host in Opts")

// Opts holds SSH/SFTP connection parameters.
type Opts struct {
	Host          string        // SSH host name or IP address (IPv6 without brackets)
	Port          int           // 0 => DefaultSSHPort (22)
	User          string        // SSH user (required)
	KeyFile       string        // path to private key (optional)
	KeyPassphrase string        // passphrase of an encrypted KeyFile (optional)
	Password      string        // plaintext password (optional); at least KeyFile or Password required
	HostKey       string        // path to known_hosts file or inline key(s), separated by " || "
	Timeout       time.Duration // limit for TCP connect, SSH handshake and SFTP start; 0 => DefaultSSHTimeout (30s)
	// KeepAliveInterval is the interval of SSH keepalive requests that detect
	// a hanging server; 0 => DefaultKeepAliveInterval, negative => disabled.
	KeepAliveInterval time.Duration
	// KeepAliveMaxMissed unanswered keepalives close the connection;
	// 0 => DefaultKeepAliveMaxMissed.
	KeepAliveMaxMissed int
}

// sshTimeout returns opts.Timeout or DefaultSSHTimeout when it is not positive.
func (o *Opts) sshTimeout() time.Duration {
	if o.Timeout <= 0 {
		return DefaultSSHTimeout
	}
	return o.Timeout
}

// keepAliveInterval returns the effective keepalive interval (0 = disabled).
func (o *Opts) keepAliveInterval() time.Duration {
	switch {
	case o.KeepAliveInterval < 0:
		return 0
	case o.KeepAliveInterval == 0:
		return DefaultKeepAliveInterval
	default:
		return o.KeepAliveInterval
	}
}

// keepAliveMaxMissed returns the effective number of tolerated missed keepalives.
func (o *Opts) keepAliveMaxMissed() int {
	if o.KeepAliveMaxMissed <= 0 {
		return DefaultKeepAliveMaxMissed
	}
	return o.KeepAliveMaxMissed
}

// port returns opts.Port or DefaultSSHPort when it is zero or negative.
func (o *Opts) port() int {
	if o.Port <= 0 {
		return DefaultSSHPort
	}
	return o.Port
}

// addr returns the dial address "host:port" (IPv6 hosts are bracketed).
func (o *Opts) addr() string {
	return net.JoinHostPort(strings.TrimSpace(o.Host), strconv.Itoa(o.port()))
}

// validateAddr checks host and port (enough to fetch the server host key).
func (o *Opts) validateAddr() error {
	if o == nil || strings.TrimSpace(o.Host) == "" {
		return ErrRemoteNotConfigured
	}
	if o.Port < 0 || o.Port > 65535 {
		return fmt.Errorf("invalid SSH port %d: must be 0..65535", o.Port)
	}
	return nil
}

// validate checks the connection parameters that every authenticated
// operation needs.
func (o *Opts) validate() error {
	if err := o.validateAddr(); err != nil {
		return err
	}
	if strings.TrimSpace(o.User) == "" {
		return fmt.Errorf("SSH user required: set User in Opts")
	}
	return nil
}

// LocalFile describes a local file for Sync (name, path, modtime, size).
type LocalFile struct {
	Name    string
	Path    string
	ModTime time.Time
	Size    int64
}

// RemoteEntry describes a remote file (name, modtime, size).
type RemoteEntry struct {
	Name    string
	ModTime time.Time
	Size    int64
}

// Logger is optional for progress and host key mismatch messages; nil = no logging.
type Logger interface {
	Info(string, ...interface{})
	Warn(string, ...interface{})
}

// KnownHostsOptions controls SSH connections that verify the server via an
// OpenSSH known_hosts file. opts.HostKey is ignored; Path is used instead.
type KnownHostsOptions struct {
	// Path to the known_hosts file (required).
	Path string
	// FetchHostKey captures the server's host key (without authenticating) and
	// appends it to Path when the file is missing or does not know the host yet
	// (trust on first use).
	FetchHostKey bool
	// TrustOnMismatch on host key mismatch fetches the current server key,
	// appends it to Path, and retries the connection once. This disables the
	// protection against man-in-the-middle attacks for changed keys.
	TrustOnMismatch bool
}
