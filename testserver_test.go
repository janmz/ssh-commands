package sshcommands

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const testPassword = "secret"

// testServer is an in-process SSH server with an in-memory SFTP file system.
type testServer struct {
	host         string
	port         int
	keyLine      string
	authAttempts atomic.Int32
	handlers     sftp.Handlers
	// ignoreGlobal drops global requests (keepalives) without replying,
	// simulating a hanging server.
	ignoreGlobal bool
}

// startTestServer starts an SSH/SFTP server on 127.0.0.1 that accepts the
// password testPassword and any public key. All connections share one
// in-memory file system.
func startTestServer(t *testing.T) *testServer {
	t.Helper()
	return startTestServerWith(t, false)
}

// startTestServerWith is startTestServer with optional hanging keepalives.
func startTestServerWith(t *testing.T, ignoreGlobal bool) *testServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	ts := &testServer{handlers: sftp.InMemHandler(), ignoreGlobal: ignoreGlobal}
	ts.keyLine = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			ts.authAttempts.Add(1)
			if string(pw) == testPassword {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
		PublicKeyCallback: func(_ ssh.ConnMetadata, _ ssh.PublicKey) (*ssh.Permissions, error) {
			ts.authAttempts.Add(1)
			return nil, nil
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	ts.host = host
	ts.port, _ = strconv.Atoi(portStr)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go ts.serve(conn, cfg)
		}
	}()
	return ts
}

func (ts *testServer) serve(conn net.Conn, cfg *ssh.ServerConfig) {
	defer closeQuietly(conn)
	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer closeQuietly(sconn)
	if ts.ignoreGlobal {
		go func() {
			for range reqs { //nolint:revive // drop requests without replying
			}
		}()
	} else {
		go ssh.DiscardRequests(reqs)
	}
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer closeQuietly(ch)
			for req := range chReqs {
				ok := req.Type == "subsystem" && len(req.Payload) > 4 && string(req.Payload[4:]) == "sftp"
				_ = req.Reply(ok, nil)
				if ok {
					srv := sftp.NewRequestServer(ch, ts.handlers)
					_ = srv.Serve()
					closeQuietly(srv)
					return
				}
			}
		}()
	}
}

// opts returns connection options for the server with inline host key.
func (ts *testServer) opts() *Opts {
	return &Opts{Host: ts.host, Port: ts.port, User: "u", Password: testPassword, HostKey: ts.keyLine}
}

// knownHostsToken returns the known_hosts host token for the server.
func (ts *testServer) knownHostsToken() string {
	return fmt.Sprintf("[%s]:%d", ts.host, ts.port)
}

// sftpClient opens a raw SFTP client for test setup and inspection.
func (ts *testServer) sftpClient(t *testing.T) *sftp.Client {
	t.Helper()
	c, s, err := NewSFTPClient(ts.opts(), nil)
	if err != nil {
		t.Fatalf("NewSFTPClient: %v", err)
	}
	t.Cleanup(func() {
		closeQuietly(c)
		closeQuietly(s)
	})
	return c
}

// recLogger records log lines for assertions.
type recLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *recLogger) Info(f string, a ...interface{}) { l.add("INFO "+f, a...) }
func (l *recLogger) Warn(f string, a ...interface{}) { l.add("WARN "+f, a...) }

func (l *recLogger) add(f string, a ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(f, a...))
}

// count returns how many lines contain sub.
func (l *recLogger) count(sub string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, s := range l.lines {
		if strings.Contains(s, sub) {
			n++
		}
	}
	return n
}
