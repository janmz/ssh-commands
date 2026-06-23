package sshcommands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFormatKnownHostsHostToken(t *testing.T) {
	t.Parallel()
	cases := []struct {
		host string
		port int
		want string
	}{
		{"example.com", 22, "example.com"},
		{"example.com", 0, "example.com"},
		{"example.com", 2222, "[example.com]:2222"},
		{"", 22, ""},
	}
	for _, c := range cases {
		got := FormatKnownHostsHostToken(c.host, c.port)
		if got != c.want {
			t.Fatalf("FormatKnownHostsHostToken(%q,%d)=%q want %q", c.host, c.port, got, c.want)
		}
	}
}

func TestAppendKnownHostsLine(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	keyLine := testEd25519Key

	if err := AppendKnownHostsLine(path, "example.com", keyLine, nil); err != nil {
		t.Fatalf("AppendKnownHostsLine: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read known_hosts: %v", err)
	}
	want := "example.com " + keyLine + "\n"
	if string(content) != want {
		t.Fatalf("known_hosts content=%q want %q", string(content), want)
	}

	if err := AppendKnownHostsLine(path, "[example.com]:2222", keyLine, nil); err != nil {
		t.Fatalf("second append: %v", err)
	}
	content, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("read known_hosts again: %v", err)
	}
	if !strings.Contains(string(content), "[example.com]:2222") {
		t.Fatalf("expected second host token in %q", string(content))
	}
}

func TestAppendKnownHostsLineValidation(t *testing.T) {
	t.Parallel()
	if err := AppendKnownHostsLine("", "", "", nil); err == nil {
		t.Fatal("expected error for empty path")
	}
	if err := AppendKnownHostsLine("known_hosts", "", "key", nil); err == nil {
		t.Fatal("expected error for empty host token")
	}
	if err := AppendKnownHostsLine("known_hosts", "host", "", nil); err == nil {
		t.Fatal("expected error for empty key line")
	}
}

func TestAppendServerHostKeySkipsWhenPresent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	keyLine := testEd25519Key
	if err := AppendKnownHostsLine(path, "example.com", keyLine, nil); err != nil {
		t.Fatalf("seed known_hosts: %v", err)
	}
	present, err := HostKeyAlreadyPresent(path, keyLine)
	if err != nil || !present {
		t.Fatalf("HostKeyAlreadyPresent=%v,%v want true,nil", present, err)
	}
}

func TestDialKnownHostsRequiresPath(t *testing.T) {
	t.Parallel()
	opts := &Opts{Host: "example.com", User: "u", Password: "p", HostKey: "ignored"}
	_, err := DialKnownHosts(opts, KnownHostsOptions{}, nil)
	if err == nil || !strings.Contains(err.Error(), "known_hosts path required") {
		t.Fatalf("DialKnownHosts empty path err=%v", err)
	}
}

func TestDialKnownHostsMissingFileWithoutFetch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "missing_known_hosts")
	opts := &Opts{Host: "example.com", User: "u", Password: "p", HostKey: "ignored"}
	_, err := DialKnownHosts(opts, KnownHostsOptions{Path: path}, nil)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("DialKnownHosts missing file err=%v", err)
	}
}

func TestNormalizeRemotePath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"/var/www/html/file.zip", "/var/www/html/file.zip"},
		{"var/www/file.zip", "/var/www/file.zip"},
		{"/a/../b", "/b"},
	}
	for _, c := range cases {
		got := normalizeRemotePath(c.in)
		if got != c.want {
			t.Fatalf("normalizeRemotePath(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestIsKnownHostsKeyMismatch(t *testing.T) {
	t.Parallel()
	if !isKnownHostsKeyMismatch(fmtError("knownhosts: key mismatch")) {
		t.Fatal("expected mismatch detection")
	}
	if isKnownHostsKeyMismatch(fmtError("connection refused")) {
		t.Fatal("did not expect mismatch for other error")
	}
}

type fmtError string

func (e fmtError) Error() string { return string(e) }
