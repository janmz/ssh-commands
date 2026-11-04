package sshcommands

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- required by the OpenSSH hashed known_hosts format
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// hostPatternIs reports whether a known_hosts host pattern denotes exactly
// token (plain or hashed "|1|salt|hash" form). Wildcard patterns never match.
func hostPatternIs(pattern, token string) bool {
	if !strings.HasPrefix(pattern, "|1|") {
		return pattern == token
	}
	parts := strings.Split(pattern, "|")
	if len(parts) != 4 {
		return false
	}
	salt, err1 := base64.StdEncoding.DecodeString(parts[2])
	want, err2 := base64.StdEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil {
		return false
	}
	mac := hmac.New(sha1.New, salt)
	mac.Write([]byte(token))
	return hmac.Equal(mac.Sum(nil), want)
}

// removeHostFromLine returns line without the host token (other hosts of a
// multi-host line are kept), and whether the line is to be kept at all.
// Marker lines (@revoked, @cert-authority), comments and unparsable lines are
// returned unchanged.
func removeHostFromLine(line, token string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "@") {
		return line, true
	}
	if _, _, _, _, _, err := ssh.ParseKnownHosts([]byte(trimmed)); err != nil {
		return line, true
	}
	fields := strings.Fields(trimmed)
	var kept []string
	for _, h := range strings.Split(fields[0], ",") {
		if !hostPatternIs(h, token) {
			kept = append(kept, h)
		}
	}
	switch {
	case len(kept) == len(strings.Split(fields[0], ",")):
		return line, true
	case len(kept) == 0:
		return "", false
	default:
		fields[0] = strings.Join(kept, ",")
		return strings.Join(fields, " "), true
	}
}

// replaceKnownHostsEntries removes all regular entries for host:port from the
// known_hosts file at p and appends keyLine for it. The file is rewritten
// atomically (temporary file + rename) with mode 0600.
func replaceKnownHostsEntries(p, host string, port int, keyLine string) (err error) {
	token, key, err := normalizeKnownHostsEntry(FormatKnownHostsHostToken(host, port), keyLine)
	if err != nil {
		return err
	}
	content, err := readLimited(p, maxKnownHostsSize)
	if err != nil {
		return fmt.Errorf("read known_hosts file: %w", err)
	}
	var lines []string
	for _, line := range strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n") {
		if l, keep := removeHostFromLine(line, token); keep {
			lines = append(lines, l)
		}
	}
	text := strings.TrimRight(strings.Join(lines, "\n"), "\n")
	if text != "" {
		text += "\n"
	}
	text += token + " " + key + "\n"

	tmp, err := os.CreateTemp(filepath.Dir(p), ".known_hosts-*")
	if err != nil {
		return fmt.Errorf("create temporary known_hosts file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err = tmp.WriteString(text); err != nil {
		closeQuietly(tmp)
		return fmt.Errorf("write known_hosts file: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("write known_hosts file: %w", err)
	}
	if err = os.Rename(tmpName, p); err != nil {
		return fmt.Errorf("replace known_hosts file: %w", err)
	}
	return nil
}
