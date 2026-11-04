package sshcommands

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh/knownhosts"
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

func TestAppendServerHostKeySkipsKnownHost(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	if err := AppendKnownHostsLine(path, "example.invalid", testEd25519Key, nil); err != nil {
		t.Fatalf("seed known_hosts: %v", err)
	}
	// The host is known, so no connection is attempted (example.invalid
	// cannot be resolved) and nothing is written.
	written, err := AppendServerHostKey(&Opts{Host: "example.invalid"}, path, nil)
	if err != nil || written {
		t.Fatalf("AppendServerHostKey=%v,%v want false,nil", written, err)
	}
}

func TestKnownHostsKnowsHost(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "known_hosts")
	if ok, err := knownHostsKnowsHost(path, "a.example", 22); err != nil || ok {
		t.Fatalf("missing file=%v,%v want false,nil", ok, err)
	}
	content := "# comment\na.example " + testEd25519Key + " user@host\n[b.example]:2222 " + testEd25519Key + "\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		host string
		port int
		want bool
	}{
		{"a.example", 22, true},
		{"a.example", 2222, false},
		{"b.example", 2222, true},
		{"b.example", 22, false},
		{"c.example", 22, false},
	}
	for _, c := range cases {
		ok, err := knownHostsKnowsHost(path, c.host, c.port)
		if err != nil || ok != c.want {
			t.Fatalf("knownHostsKnowsHost(%s,%d)=%v,%v want %v", c.host, c.port, ok, err, c.want)
		}
	}
}

func TestAppendKnownHostsLineAddsMissingNewline(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte("a.example "+testEd25519Key), 0600); err != nil {
		t.Fatal(err)
	}
	if err := AppendKnownHostsLine(path, "b.example", testEd25519Key, nil); err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(path)
	want := "a.example " + testEd25519Key + "\nb.example " + testEd25519Key + "\n"
	if string(content) != want {
		t.Fatalf("content=%q want %q", content, want)
	}
}

func TestAppendKnownHostsLineRejectsInjection(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "known_hosts")
	for _, tok := range []string{"a\nevil.example", "a\x00b", "*", "*.example.com", "a,b", "!a", "@revoked", "a b", "[a]:x"} {
		if err := AppendKnownHostsLine(path, tok, testEd25519Key, nil); err == nil {
			t.Fatalf("token %q must be rejected", tok)
		}
	}
	if err := AppendKnownHostsLine(path, "a", testEd25519Key+"\n@revoked * "+testEd25519Key, nil); err == nil {
		t.Fatal("key line with newline must be rejected")
	}
	if err := AppendKnownHostsLine(path, "a", "not-a-key", nil); err == nil {
		t.Fatal("invalid key line must be rejected")
	}
	if err := AppendKnownHostsLine(path, "a", `command="x" `+testEd25519Key, nil); err == nil {
		t.Fatal("key line with options must be rejected")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("nothing may be written for rejected entries: %v", err)
	}
	for _, tok := range []string{"example.com", "[example.com]:2222", "::1", "[2001:db8::1]:22", "|1|F1E1KeoE/eEWhi10WpGv4OdiO6Y=|3988QV0VE8wmZL7suNrYQLITLCg="} {
		if err := AppendKnownHostsLine(path, tok, testEd25519Key+" comment is dropped", nil); err != nil {
			t.Fatalf("token %q: %v", tok, err)
		}
	}
	content, _ := os.ReadFile(path)
	if strings.Contains(string(content), "comment") {
		t.Fatalf("comment must be dropped: %q", content)
	}
}

func TestReplaceKnownHostsEntries(t *testing.T) {
	t.Parallel()
	const newKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDpQrfDm6rCW8i6QZf7Zh8wQ8RWm0d/0gvTzB3o7lGqn"
	hashed := hashHostForTest(t, "target.example")
	seed := "# keep me\r\n" +
		"target.example " + testEd25519Key + "\n" +
		hashed + " " + testEd25519Key + "\n" +
		"target.example,alias.example " + testEd25519Key + " c\n" +
		"@revoked target.example " + testEd25519Key + "\n" +
		"*.example " + testEd25519Key + "\n" +
		"[target.example]:2222 " + testEd25519Key
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte(seed), 0600); err != nil {
		t.Fatal(err)
	}
	if err := replaceKnownHostsEntries(path, "target.example", 22, newKey); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	want := "# keep me\n" +
		"alias.example " + testEd25519Key + " c\n" +
		"@revoked target.example " + testEd25519Key + "\n" +
		"*.example " + testEd25519Key + "\n" +
		"[target.example]:2222 " + testEd25519Key + "\n" +
		"target.example " + newKey + "\n"
	if string(got) != want {
		t.Fatalf("known_hosts=%q\nwant      %q", got, want)
	}
}

// hashHostForTest builds an OpenSSH hashed host token for host.
func hashHostForTest(t *testing.T, host string) string {
	t.Helper()
	tok := knownhosts.HashHostname(host)
	if !hostPatternIs(tok, host) || hostPatternIs(tok, "other.example") {
		t.Fatalf("hashed token %q does not match correctly", tok)
	}
	return tok
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
	mismatch := fmt.Errorf("ssh: handshake failed: %w", &knownhosts.KeyError{Want: []knownhosts.KnownKey{{}}})
	if !isKnownHostsKeyMismatch(mismatch) {
		t.Fatal("expected mismatch detection")
	}
	if isKnownHostsKeyMismatch(&knownhosts.KeyError{}) {
		t.Fatal("unknown host is not a mismatch")
	}
	if isKnownHostsKeyMismatch(errors.New("knownhosts: key mismatch")) {
		t.Fatal("plain error text must not count as mismatch")
	}
}
