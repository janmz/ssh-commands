package sshcommands

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// writeLocal creates a local file with content and an mtime in the past.
func writeLocal(t *testing.T, dir, name, content string) LocalFile {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	mt := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(p, mt, mt); err != nil {
		t.Fatal(err)
	}
	return LocalFile{Name: name, Path: p, ModTime: mt, Size: int64(len(content))}
}

func TestFetchServerHostKeySendsNoCredentials(t *testing.T) {
	t.Parallel()
	ts := startTestServer(t)
	key, err := FetchServerHostKey(&Opts{Host: ts.host, Port: ts.port, Password: "must-not-be-sent"})
	if err != nil {
		t.Fatalf("FetchServerHostKey: %v", err)
	}
	if key != ts.keyLine {
		t.Fatalf("key=%q want %q", key, ts.keyLine)
	}
	if n := ts.authAttempts.Load(); n != 0 {
		t.Fatalf("auth attempts=%d want 0", n)
	}
}

func TestSyncDownloadRoundTrip(t *testing.T) {
	t.Parallel()
	for _, pw := range []string{"", " aes-pw\n"} {
		ts := startTestServer(t)
		opts := ts.opts()
		src := t.TempDir()
		files := []LocalFile{
			writeLocal(t, src, "a.txt", "alpha content"),
			writeLocal(t, src, "b.txt", strings.Repeat("b", 5000)),
		}
		log := &recLogger{}
		if err := Sync(opts, files, "/backups", pw, log); err != nil {
			t.Fatalf("Sync(pw=%q): %v", pw, err)
		}
		if n := log.count("uploaded"); n != 2 {
			t.Fatalf("uploads=%d want 2", n)
		}
		entries, err := List(opts, "/backups", nil)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(entries) != 2 {
			t.Fatalf("entries=%v (temp files must be gone)", entries)
		}
		overhead := int64(0)
		if pw != "" {
			overhead = EncryptionOverhead
		}
		for _, e := range entries {
			for _, f := range files {
				if f.Name == e.Name && e.Size != f.Size+overhead {
					t.Fatalf("%s size=%d want %d", e.Name, e.Size, f.Size+overhead)
				}
			}
		}

		// Unchanged files are not uploaded again.
		log2 := &recLogger{}
		if err := Sync(opts, files, "/backups", pw, log2); err != nil {
			t.Fatalf("second Sync: %v", err)
		}
		if n := log2.count("uploaded"); n != 0 {
			t.Fatalf("second Sync uploads=%d want 0", n)
		}

		dest := t.TempDir()
		paths, err := Download(opts, "*.txt", dest, "/backups", strings.TrimSpace(pw), nil)
		if err != nil {
			t.Fatalf("Download: %v", err)
		}
		if len(paths) != 2 {
			t.Fatalf("paths=%v", paths)
		}
		for _, f := range files {
			want, _ := os.ReadFile(f.Path)
			got, err := os.ReadFile(filepath.Join(dest, f.Name))
			if err != nil || string(got) != string(want) {
				t.Fatalf("%s content mismatch: %v", f.Name, err)
			}
		}
		// A second download must not overwrite: it goes to .lokal, then .lokal.2.
		for _, suffix := range []string{".lokal", ".lokal.2"} {
			paths, err = Download(opts, "a.txt", dest, "/backups", pw, nil)
			if err != nil {
				t.Fatalf("Download again: %v", err)
			}
			if want := filepath.Join(dest, "a.txt"+suffix); paths[0] != want {
				t.Fatalf("path=%q want %q", paths[0], want)
			}
		}
		assertNoPartFiles(t, dest)
	}
}

func assertNoPartFiles(t *testing.T, dir string) {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range des {
		if strings.Contains(de.Name(), ".part-") {
			t.Fatalf("leftover temp file %s", de.Name())
		}
	}
}

func TestDownloadWrongPasswordLeavesNothing(t *testing.T) {
	t.Parallel()
	ts := startTestServer(t)
	opts := ts.opts()
	files := []LocalFile{writeLocal(t, t.TempDir(), "x.bin", "payload")}
	if err := Sync(opts, files, "/d", "right", nil); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	_, err := Download(opts, "x.bin", dest, "/d", "wrong", nil)
	if !errors.Is(err, ErrDecryptIntegrity) {
		t.Fatalf("err=%v want ErrDecryptIntegrity", err)
	}
	des, _ := os.ReadDir(dest)
	if len(des) != 0 {
		t.Fatalf("dest not empty: %v", des)
	}
}

func TestSyncPrunesAndRemovesLeftovers(t *testing.T) {
	t.Parallel()
	ts := startTestServer(t)
	opts := ts.opts()
	c := ts.sftpClient(t)
	if err := c.MkdirAll("/p"); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"old.txt", tempUploadPrefix + "keep.txt"} {
		f, err := c.Create("/p/" + n)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write([]byte("x"))
		closeQuietly(f)
	}
	files := []LocalFile{writeLocal(t, t.TempDir(), "keep.txt", "k")}
	if err := Sync(opts, files, "/p", "", nil); err != nil {
		t.Fatal(err)
	}
	entries, err := List(opts, "/p", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "keep.txt" {
		t.Fatalf("entries=%v want only keep.txt", entries)
	}
}

func TestSyncReplacesPartialUpload(t *testing.T) {
	t.Parallel()
	ts := startTestServer(t)
	opts := ts.opts()
	c := ts.sftpClient(t)
	if err := c.MkdirAll("/r"); err != nil {
		t.Fatal(err)
	}
	// A partial file (newer mtime, smaller size) must be replaced.
	f, err := c.Create("/r/big.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte("par"))
	closeQuietly(f)
	files := []LocalFile{writeLocal(t, t.TempDir(), "big.txt", "complete content")}
	if err := Sync(opts, files, "/r", "", nil); err != nil {
		t.Fatal(err)
	}
	rf, err := c.Open("/r/big.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer closeQuietly(rf)
	got, _ := io.ReadAll(rf)
	if string(got) != "complete content" {
		t.Fatalf("remote=%q", got)
	}
}

func TestSyncValidatesBeforeConnect(t *testing.T) {
	t.Parallel()
	// Port 1 on localhost is not listening; validation must fail first.
	opts := &Opts{Host: "127.0.0.1", Port: 1, User: "u", Password: "p", HostKey: testEd25519Key}
	dir := t.TempDir()
	ok := writeLocal(t, dir, "ok.txt", "x")
	cases := map[string][]LocalFile{
		"empty list": nil,
		"traversal":  {ok, {Name: "../x", Path: ok.Path}},
		"duplicate":  {ok, ok},
		"reserved":   {{Name: tempUploadPrefix + "a", Path: ok.Path}},
		"empty path": {{Name: "a"}},
	}
	for name, files := range cases {
		err := Sync(opts, files, "/x", "", nil)
		if err == nil || strings.Contains(err.Error(), "connect") {
			t.Fatalf("%s: err=%v want validation error", name, err)
		}
	}
	if err := Sync(opts, []LocalFile{ok}, " ", "", nil); err == nil || !strings.Contains(err.Error(), "remote directory") {
		t.Fatalf("empty remoteDir err=%v", err)
	}
	if err := Sync(&Opts{}, []LocalFile{ok}, "/x", "", nil); !errors.Is(err, ErrRemoteNotConfigured) {
		t.Fatalf("empty host err=%v", err)
	}
}

func TestDeleteCollectsErrors(t *testing.T) {
	t.Parallel()
	ts := startTestServer(t)
	opts := ts.opts()
	files := []LocalFile{writeLocal(t, t.TempDir(), "a.txt", "a")}
	if err := Sync(opts, files, "/del", "", nil); err != nil {
		t.Fatal(err)
	}
	// Invalid name: rejected before anything is deleted.
	if err := Delete(opts, "/del", []string{"a.txt", "../x"}, nil); err == nil {
		t.Fatal("expected error for invalid name")
	}
	if entries, _ := List(opts, "/del", nil); len(entries) != 1 {
		t.Fatalf("a.txt must still exist: %v", entries)
	}
	err := Delete(opts, "/del", []string{"missing.txt", "a.txt"}, nil)
	if err == nil || !strings.Contains(err.Error(), "missing.txt") {
		t.Fatalf("err=%v want error for missing.txt", err)
	}
	if entries, _ := List(opts, "/del", nil); len(entries) != 0 {
		t.Fatalf("a.txt must be deleted: %v", entries)
	}
}

func TestUploadFileIfNewer(t *testing.T) {
	t.Parallel()
	ts := startTestServer(t)
	opts := ts.opts()
	client, err := DialWithHostKeyCallback(opts, mustHostKeyCallback(t, ts.keyLine), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeQuietly(client)
	f := writeLocal(t, t.TempDir(), "u.txt", "upload me")
	log := &recLogger{}
	if err := UploadFileIfNewer(client, f.Path, "/up/dir/u.txt", log); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if err := UploadFileIfNewer(client, f.Path, "/up/dir/u.txt", log); err != nil {
		t.Fatalf("second upload: %v", err)
	}
	if n := log.count("INFO uploaded"); n != 1 {
		t.Fatalf("uploads=%d want 1", n)
	}
	if n := log.count("already current"); n != 1 {
		t.Fatalf("already current=%d want 1", n)
	}
}

func mustHostKeyCallback(t *testing.T, keyLine string) ssh.HostKeyCallback {
	t.Helper()
	cb, err := hostKeyCallback(keyLine, nil)
	if err != nil {
		t.Fatal(err)
	}
	return cb
}

func TestDialKnownHostsFetchAndMismatch(t *testing.T) {
	t.Parallel()
	ts := startTestServer(t)
	opts := ts.opts()
	path := filepath.Join(t.TempDir(), "sub", "known_hosts")

	client, err := DialKnownHosts(opts, KnownHostsOptions{Path: path, FetchHostKey: true}, nil)
	if err != nil {
		t.Fatalf("DialKnownHosts fetch: %v", err)
	}
	closeQuietly(client)
	content, _ := os.ReadFile(path)
	if want := ts.knownHostsToken() + " " + ts.keyLine + "\n"; string(content) != want {
		t.Fatalf("known_hosts=%q want %q", content, want)
	}
	// Second connect must not append a duplicate.
	client, err = DialKnownHosts(opts, KnownHostsOptions{Path: path, FetchHostKey: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	closeQuietly(client)
	if again, _ := os.ReadFile(path); string(again) != string(content) {
		t.Fatalf("known_hosts changed: %q", again)
	}

	// Wrong key for the host: mismatch without TrustOnMismatch, even with FetchHostKey.
	wrong := filepath.Join(t.TempDir(), "known_hosts")
	other := "other.example " + testEd25519Key
	seed := "# comment\n" + other + "\n" + ts.knownHostsToken() + "," + "alias.example " + testEd25519Key + " comment"
	if err := os.WriteFile(wrong, []byte(seed), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = DialKnownHosts(opts, KnownHostsOptions{Path: wrong, FetchHostKey: true}, nil)
	if !isKnownHostsKeyMismatch(err) {
		t.Fatalf("err=%v want key mismatch", err)
	}
	log := &recLogger{}
	client, err = DialKnownHosts(opts, KnownHostsOptions{Path: wrong, TrustOnMismatch: true}, log)
	if err != nil {
		t.Fatalf("TrustOnMismatch: %v", err)
	}
	closeQuietly(client)
	// The old entry for the host is replaced; other hosts (including the
	// alias on the same line) and comments are kept.
	content, _ = os.ReadFile(wrong)
	want := "# comment\n" + other + "\nalias.example " + testEd25519Key + " comment\n" +
		ts.knownHostsToken() + " " + ts.keyLine + "\n"
	if string(content) != want {
		t.Fatalf("known_hosts after trust=%q\nwant %q", content, want)
	}
	if log.count("replaces its known_hosts entries with key fingerprint SHA256:") != 1 {
		t.Fatalf("new fingerprint not logged: %v", log.lines)
	}
}

func TestKeepAliveClosesHangingConnection(t *testing.T) {
	t.Parallel()
	ts := startTestServerWith(t, true)
	opts := ts.opts()
	opts.KeepAliveInterval = 100 * time.Millisecond
	opts.KeepAliveMaxMissed = 2
	client, err := DialWithHostKeyCallback(opts, mustHostKeyCallback(t, ts.keyLine), nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		_ = client.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		closeQuietly(client)
		t.Fatal("connection to hanging server was not closed by keepalive")
	}
}

func TestKeepAliveKeepsHealthyConnection(t *testing.T) {
	t.Parallel()
	ts := startTestServer(t)
	opts := ts.opts()
	opts.KeepAliveInterval = 50 * time.Millisecond
	client, err := DialWithHostKeyCallback(opts, mustHostKeyCallback(t, ts.keyLine), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeQuietly(client)
	time.Sleep(400 * time.Millisecond)
	if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
		t.Fatalf("healthy connection was closed: %v", err)
	}
}

func TestEncryptedPrivateKey(t *testing.T) {
	t.Parallel()
	ts := startTestServer(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("phrase"))
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	opts := &Opts{Host: ts.host, Port: ts.port, User: "u", KeyFile: keyFile, HostKey: ts.keyLine}
	if _, err := List(opts, "/", nil); err == nil || !strings.Contains(err.Error(), "KeyPassphrase") {
		t.Fatalf("missing passphrase err=%v", err)
	}
	opts.KeyPassphrase = "wrong"
	if _, err := List(opts, "/", nil); err == nil {
		t.Fatal("wrong passphrase must fail")
	}
	opts.KeyPassphrase = "phrase"
	if _, err := List(opts, "/", nil); err != nil {
		t.Fatalf("List with passphrase: %v", err)
	}
}

func TestDownloadOptionsAndValidation(t *testing.T) {
	t.Parallel()
	ts := startTestServer(t)
	opts := ts.opts()
	files := []LocalFile{writeLocal(t, t.TempDir(), "big.txt", strings.Repeat("x", 1000))}
	if err := Sync(opts, files, "/o", "", nil); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if _, err := DownloadWithOptions(opts, "big.txt", dest, "/o", "", DownloadOptions{MaxSize: 999}, nil); !errors.Is(err, ErrDownloadTooLarge) {
		t.Fatalf("MaxSize err=%v want ErrDownloadTooLarge", err)
	}
	if _, err := DownloadWithOptions(opts, "big.txt", dest, "/o", "", DownloadOptions{MaxSize: 1000}, nil); err != nil {
		t.Fatalf("MaxSize equal: %v", err)
	}
	if _, err := Download(opts, "big.txt", " ", "/o", "", nil); err == nil || !strings.Contains(err.Error(), "destination") {
		t.Fatalf("empty destDir err=%v", err)
	}
	if _, err := Download(opts, "big.txt", dest, "/o", "pw", nil); !errors.Is(err, ErrNotEncrypted) {
		t.Fatalf("plain file with password err=%v want ErrNotEncrypted", err)
	}
	for _, bad := range []string{".", "a\nb"} {
		if _, err := Download(opts, bad, dest, "/o", "", nil); err == nil {
			t.Fatalf("pattern %q must be rejected", bad)
		}
		if err := Delete(opts, "/o", []string{bad}, nil); err == nil {
			t.Fatalf("Delete(%q) must be rejected", bad)
		}
	}
	assertNoPartFiles(t, dest)
}

func TestMaxReader(t *testing.T) {
	t.Parallel()
	r := &maxReader{r: strings.NewReader("12345"), remaining: 4}
	if _, err := io.ReadAll(r); !errors.Is(err, ErrDownloadTooLarge) {
		t.Fatalf("err=%v want ErrDownloadTooLarge", err)
	}
	r = &maxReader{r: strings.NewReader("1234"), remaining: 4}
	if got, err := io.ReadAll(r); err != nil || string(got) != "1234" {
		t.Fatalf("exact size: %q %v", got, err)
	}
}

func TestHandshakeTimeout(t *testing.T) {
	t.Parallel()
	// A server that accepts TCP but never speaks SSH.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer closeQuietly(ln)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer closeQuietly(c)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	opts := &Opts{Host: "127.0.0.1", Port: addr.Port, User: "u", Password: "p", HostKey: testEd25519Key, Timeout: 300 * time.Millisecond}
	start := time.Now()
	_, err = List(opts, "/", nil)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("handshake not bounded: %v", d)
	}
}
