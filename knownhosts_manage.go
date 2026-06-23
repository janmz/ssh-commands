package sshcommands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// FormatKnownHostsHostToken returns the host token for a known_hosts entry.
func FormatKnownHostsHostToken(host string, port int) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if port > 0 && port != 22 {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return host
}

// AppendKnownHostsLine appends a host token and key line to a known_hosts file.
// Parent directories are created as needed.
func AppendKnownHostsLine(knownHostsPath, hostToken, keyLine string, log Logger) error {
	hostToken = strings.TrimSpace(hostToken)
	keyLine = strings.TrimSpace(keyLine)
	if hostToken == "" {
		return fmt.Errorf("known_hosts host token is empty")
	}
	if keyLine == "" {
		return fmt.Errorf("known_hosts key line is empty")
	}
	path := filepath.FromSlash(strings.TrimSpace(knownHostsPath))
	if path == "" {
		return fmt.Errorf("known_hosts path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create known_hosts directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600) // #nosec G304
	if err != nil {
		return fmt.Errorf("open known_hosts file: %w", err)
	}
	defer f.Close()
	entry := fmt.Sprintf("%s %s\n", hostToken, keyLine)
	if _, err := f.WriteString(entry); err != nil {
		return fmt.Errorf("write known_hosts file: %w", err)
	}
	if log != nil {
		log.Info("SSH host key appended to known_hosts: %s", path)
	}
	return nil
}

// AppendServerHostKey fetches the server host key and appends it to knownHostsPath
// when it is not already present. Returns written=true when a new line was added.
func AppendServerHostKey(opts *Opts, knownHostsPath string, log Logger) (written bool, err error) {
	keyLine, err := FetchServerHostKey(opts)
	if err != nil {
		return false, err
	}
	present, err := HostKeyAlreadyPresent(knownHostsPath, keyLine)
	if err != nil {
		return false, err
	}
	if present {
		return false, nil
	}
	port := opts.Port
	if port <= 0 {
		port = 22
	}
	hostToken := FormatKnownHostsHostToken(opts.Host, port)
	if err := AppendKnownHostsLine(knownHostsPath, hostToken, keyLine, log); err != nil {
		return false, err
	}
	return true, nil
}
