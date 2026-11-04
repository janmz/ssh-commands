package sshcommands

import (
	"errors"
	"testing"
	"time"
)

func TestValidRemoteFileName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"backup.zip", true},
		{"backup_2026-01-01.tar.gz", true},
		{".hidden", true},
		{"", false},
		{"..", false},
		{"../etc/passwd", false},
		{"a..b", false},
		{"dir/file", false},
		{`dir\file`, false},
		{"/abs", false},
		{".", false},
		{"a\nb", false},
		{"a\x00b", false},
		{"esc\x1b[31m", false},
		{"del\x7f", false},
		{"tab\there", false},
		{"ümlaut ok.txt", true},
	}
	for _, c := range cases {
		if got := ValidRemoteFileName(c.name); got != c.want {
			t.Errorf("ValidRemoteFileName(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestValidLocalFileName(t *testing.T) {
	cases := []struct {
		name             string
		unix, windowsRes bool
	}{
		{"backup.zip", true, true},
		{"CON", true, false},
		{"nul.txt", true, false},
		{"com1.tar.gz", true, false},
		{"console.txt", true, true},
		{"trailing.", true, false},
		{"trailing ", true, false},
		{"a:b", true, false},
		{"a?b", true, false},
		{".", false, false},
	}
	for _, c := range cases {
		if got := validLocalFileName(c.name, false); got != c.unix {
			t.Errorf("validLocalFileName(%q, unix) = %v, want %v", c.name, got, c.unix)
		}
		if got := validLocalFileName(c.name, true); got != c.windowsRes {
			t.Errorf("validLocalFileName(%q, windows) = %v, want %v", c.name, got, c.windowsRes)
		}
	}
}

func TestKeepAliveDefaults(t *testing.T) {
	if got := (&Opts{}).keepAliveInterval(); got != DefaultKeepAliveInterval {
		t.Errorf("default interval = %v", got)
	}
	if got := (&Opts{KeepAliveInterval: -1}).keepAliveInterval(); got != 0 {
		t.Errorf("negative interval must disable keepalive, got %v", got)
	}
	if got := (&Opts{}).keepAliveMaxMissed(); got != DefaultKeepAliveMaxMissed {
		t.Errorf("default max missed = %d", got)
	}
}

func TestValidDownloadPatternWildcards(t *testing.T) {
	if !ValidDownloadPattern("backup_*.zip") {
		t.Error("wildcard pattern without path components must be valid")
	}
	if ValidDownloadPattern("../*.zip") {
		t.Error("pattern with .. must be invalid")
	}
}

func TestOptsAddrAndValidate(t *testing.T) {
	cases := []struct {
		host string
		port int
		want string
	}{
		{"example.com", 0, "example.com:22"},
		{" example.com ", 2222, "example.com:2222"},
		{"::1", 0, "[::1]:22"},
		{"2001:db8::1", 2200, "[2001:db8::1]:2200"},
	}
	for _, c := range cases {
		if got := (&Opts{Host: c.host, Port: c.port}).addr(); got != c.want {
			t.Errorf("addr(%q,%d)=%q want %q", c.host, c.port, got, c.want)
		}
	}
	if err := (&Opts{User: "u"}).validate(); !errors.Is(err, ErrRemoteNotConfigured) {
		t.Errorf("empty host err=%v", err)
	}
	if err := (*Opts)(nil).validate(); !errors.Is(err, ErrRemoteNotConfigured) {
		t.Errorf("nil opts err=%v", err)
	}
	for _, p := range []int{-1, 65536} {
		if err := (&Opts{Host: "h", User: "u", Port: p}).validate(); err == nil {
			t.Errorf("port %d must be rejected", p)
		}
	}
	if err := (&Opts{Host: "h"}).validate(); err == nil {
		t.Error("empty user must be rejected")
	}
	if err := (&Opts{Host: "h"}).validateAddr(); err != nil {
		t.Errorf("validateAddr without user: %v", err)
	}
}

func TestCleanRemoteDir(t *testing.T) {
	for in, want := range map[string]string{"/a/b/": "/a/b", "backups": "backups", "/a/../b": "/b", "/": "/"} {
		got, err := cleanRemoteDir(in)
		if err != nil || got != want {
			t.Errorf("cleanRemoteDir(%q)=%q,%v want %q", in, got, err, want)
		}
	}
	if _, err := cleanRemoteDir("  "); err == nil {
		t.Error("empty remote dir must be rejected")
	}
}

func TestNeedsUpload(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	loc := LocalFile{Name: "f", ModTime: base.Add(700 * time.Millisecond), Size: 100}
	cases := []struct {
		name    string
		rem     RemoteEntry
		exists  bool
		encrypt bool
		want    bool
	}{
		{"missing", RemoteEntry{}, false, false, true},
		{"same second, same size", RemoteEntry{ModTime: base, Size: 100}, true, false, false},
		{"remote newer", RemoteEntry{ModTime: base.Add(time.Hour), Size: 100}, true, false, false},
		{"local newer", RemoteEntry{ModTime: base.Add(-time.Second), Size: 100}, true, false, true},
		{"partial upload (newer, smaller)", RemoteEntry{ModTime: base.Add(time.Hour), Size: 40}, true, false, true},
		{"encrypted ok", RemoteEntry{ModTime: base, Size: 100 + EncryptionOverhead}, true, true, false},
		{"encryption switched on", RemoteEntry{ModTime: base, Size: 100}, true, true, true},
		{"encryption switched off", RemoteEntry{ModTime: base, Size: 100 + EncryptionOverhead}, true, false, true},
	}
	for _, c := range cases {
		if got := needsUpload(loc, c.rem, c.exists, c.encrypt); got != c.want {
			t.Errorf("%s: needsUpload=%v want %v", c.name, got, c.want)
		}
	}
}

func TestOptsSSHTimeout(t *testing.T) {
	if got := (&Opts{}).sshTimeout(); got != DefaultSSHTimeout {
		t.Errorf("zero timeout = %v, want %v", got, DefaultSSHTimeout)
	}
	if got := (&Opts{Timeout: -time.Second}).sshTimeout(); got != DefaultSSHTimeout {
		t.Errorf("negative timeout = %v, want %v", got, DefaultSSHTimeout)
	}
	if got := (&Opts{Timeout: 5 * time.Second}).sshTimeout(); got != 5*time.Second {
		t.Errorf("explicit timeout = %v, want 5s", got)
	}
}
