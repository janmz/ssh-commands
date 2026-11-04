package sshcommands

import (
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
	}
	for _, c := range cases {
		if got := ValidRemoteFileName(c.name); got != c.want {
			t.Errorf("ValidRemoteFileName(%q) = %v, want %v", c.name, got, c.want)
		}
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
