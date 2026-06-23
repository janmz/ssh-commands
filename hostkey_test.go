package sshcommands

import (
	"os"
	"path/filepath"
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
}

func TestHostKeyAlreadyPresentFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	key := testEd25519Key
	if err := os.WriteFile(path, []byte("example.com "+key+"\n"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	ok, err := HostKeyAlreadyPresent(path, key)
	if err != nil || !ok {
		t.Fatalf("HostKeyAlreadyPresent file=%v,%v want true,nil", ok, err)
	}
}
