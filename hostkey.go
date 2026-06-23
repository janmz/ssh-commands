package sshcommands

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// FetchServerHostKey connects to the SSH server without host key verification,
// captures the server's host key, and returns it as a single line (key-type base64…).
// The client is closed immediately. Use for initial setup (e.g. -setup-ssh).
func FetchServerHostKey(opts *Opts) (keyLine string, err error) {
	if opts.Host == "" {
		return "", fmt.Errorf("remote not configured: set Host in Opts")
	}
	var capturedKey ssh.PublicKey
	hostKeyCB := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		capturedKey = key
		return nil
	}
	var auth []ssh.AuthMethod
	if opts.KeyFile != "" {
		keyPath := filepath.FromSlash(opts.KeyFile)
		key, err := os.ReadFile(keyPath)
		if err != nil {
			return "", fmt.Errorf("read key file: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return "", fmt.Errorf("parse private key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if opts.Password != "" {
		auth = append(auth, ssh.Password(opts.Password))
	}
	if len(auth) == 0 {
		return "", fmt.Errorf("no SSH auth: set KeyFile or Password in Opts")
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
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return "", err
	}
	defer client.Close()
	if capturedKey == nil {
		return "", fmt.Errorf("server did not send a host key")
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(capturedKey))), nil
}

// HostKeyAlreadyPresent returns true if newKeyLine is already among the keys in
// currentValue (inline " || "-separated keys or path to a file with one key per line).
func HostKeyAlreadyPresent(currentValue, newKeyLine string) (bool, error) {
	newKeyLine = strings.TrimSpace(newKeyLine)
	if newKeyLine == "" {
		return false, nil
	}
	newPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(newKeyLine))
	if err != nil {
		return false, nil
	}
	newMarshal := newPub.Marshal()
	currentValue = strings.TrimSpace(currentValue)
	var lines []string
	path := filepath.FromSlash(currentValue)
	if currentValue != "" {
		if fi, err := os.Stat(path); err == nil && fi.Mode().IsRegular() {
			content, err := os.ReadFile(path)
			if err != nil {
				return false, err
			}
			for _, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					lines = append(lines, line)
				}
			}
		} else {
			for _, block := range strings.Split(currentValue, "||") {
				block = strings.ReplaceAll(block, "\r\n", "\n")
				block = strings.ReplaceAll(block, "\r", "\n")
				for _, line := range strings.Split(block, "\n") {
					line = strings.TrimSpace(line)
					if line != "" {
						lines = append(lines, line)
					}
				}
			}
		}
	}
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		keyPart := strings.Join(parts[len(parts)-2:], " ")
		existing, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keyPart))
		if err != nil {
			continue
		}
		if bytes.Equal(existing.Marshal(), newMarshal) {
			return true, nil
		}
	}
	return false, nil
}
