// Package sshcommands provides SSH/SFTP operations (upload, list, delete,
// download, fetch host key) with parameter-based API, no config dependency.
package sshcommands

import "time"

// Opts holds SSH/SFTP connection parameters.
type Opts struct {
	Host     string // SSH host
	Port     int    // 0 => 22
	User     string
	KeyFile  string // path to private key (optional)
	Password string // plaintext password (optional); at least KeyFile or Password required
	HostKey  string // path to known_hosts file or inline key(s), separated by " || "
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
	// FetchHostKey connects to the server, captures its host key, and appends
	// it to Path when the file is missing or does not yet contain that key.
	FetchHostKey bool
	// TrustOnMismatch on host key mismatch fetches the current server key,
	// appends it to Path, and retries the connection once.
	TrustOnMismatch bool
}
