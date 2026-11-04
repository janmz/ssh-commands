package sshcommands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testEd25519Key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIGS5DWEp+t+cBJBv1tuhxB9PBjWTRx0j5zbE6ODZjRb"

func TestHostKeyAlreadyPresentInline(t *testing.T) {
	t.Parallel()
	key := testEd25519Key
	inline := key + " || " + testEd25519Key
	ok, err := HostKeyAlreadyPresent(inline, key)
	if err != nil || !ok {
		t.Fatalf("HostKeyAlreadyPresent inline=%v,%v want true,nil", ok, err)
	}
	ok, err = HostKeyAlreadyPresent(inline, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINotThere")
	if err != nil || ok {
		t.Fatalf("HostKeyAlreadyPresent missing=%v,%v want false,nil", ok, err)
	}
	ok, err = HostKeyAlreadyPresent(key+" user@host", key)
	if err != nil || !ok {
		t.Fatalf("inline key with comment=%v,%v want true,nil", ok, err)
	}
}

func TestHostKeyAlreadyPresentFile(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, content string
		want          bool
	}{
		{"plain", "example.com " + testEd25519Key + "\n", true},
		{"with comment", "example.com " + testEd25519Key + " user@host\n", true},
		{"hashed host", "|1|F1E1KeoE/eEWhi10WpGv4OdiO6Y=|3988QV0VE8wmZL7suNrYQLITLCg= " + testEd25519Key + "\n", true},
		{"revoked", "example.com " + testEd25519Key + "\n@revoked * " + testEd25519Key + "\n", false},
		{"cert authority", "@cert-authority *.example.com " + testEd25519Key + "\n", false},
		{"other key", "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDpQrfDm6rCW8i6QZf7Zh8wQ8RWm0d/0gvTzB3o7lGqn\n", false},
	}
	for _, c := range cases {
		path := filepath.Join(t.TempDir(), "known_hosts")
		if err := os.WriteFile(path, []byte(c.content), 0600); err != nil {
			t.Fatalf("write file: %v", err)
		}
		ok, err := HostKeyAlreadyPresent(path, testEd25519Key)
		if err != nil || ok != c.want {
			t.Fatalf("%s: HostKeyAlreadyPresent=%v,%v want %v", c.name, ok, err, c.want)
		}
	}
}

func TestParseInlineHostKeys(t *testing.T) {
	t.Parallel()
	valid := []string{
		testEd25519Key,
		testEd25519Key + " comment with spaces",
		"example.com " + testEd25519Key,
		"[example.com]:2222 " + testEd25519Key + " comment",
		"# header\n" + testEd25519Key + "\r\n\r\n",
		testEd25519Key + " || " + testEd25519Key + " c",
	}
	for _, v := range valid {
		if _, err := parseInlineHostKeys(v); err != nil {
			t.Fatalf("parseInlineHostKeys(%q): %v", v, err)
		}
	}
	invalid := map[string]string{
		testEd25519Key + " || garbage": "entry 2",
		"@revoked * " + testEd25519Key: "marker",
		"   ":                          "no key",
	}
	for v, wantSub := range invalid {
		_, err := parseInlineHostKeys(v)
		if err == nil || !strings.Contains(err.Error(), wantSub) {
			t.Fatalf("parseInlineHostKeys(%q) err=%v want %q", v, err, wantSub)
		}
	}
}

func TestHostKeyCallbackPathErrors(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "no_such_known_hosts")
	for _, v := range []string{missing, "known_hosts_typo", `C:\Users\Some One\.ssh\known_hosts`} {
		_, err := hostKeyCallback(v, nil)
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("hostKeyCallback(%q) err=%v want not found", v, err)
		}
	}
	if _, err := hostKeyCallback(t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory err=%v", err)
	}
	if _, err := hostKeyCallback("", nil); err == nil {
		t.Fatal("empty host key must fail")
	}
}
