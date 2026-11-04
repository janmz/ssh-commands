# ssh-commands

Go library for SSH/SFTP operations with a parameter-based API: upload (sync),
list, delete, download, and fetch server host keys. No config struct dependency;
all options are passed as parameters. Optional authenticated encryption
(AES-256-CTR + HMAC-SHA256) for upload/download.

[![Go Reference](https://pkg.go.dev/badge/github.com/janmz/ssh-commands.svg)](https://pkg.go.dev/github.com/janmz/ssh-commands)
[![Go Report Card](https://goreportcard.com/badge/github.com/janmz/ssh-commands)](https://goreportcard.com/report/github.com/janmz/ssh-commands)
[![CI](https://github.com/janmz/ssh-commands/actions/workflows/ci.yml/badge.svg)](https://github.com/janmz/ssh-commands/actions/workflows/ci.yml)

[🇩🇪 Deutsche Version](README.de.md)

**Donationware for [CFI Kinderhilfe](https://cfi-kinderhilfe.de/jetzt-spenden/?q=VAYASSH).**
License: MIT with attribution (see [LICENSE](LICENSE)).

## Requirements

- Go 1.26 or later (see `go.mod`)

## Installation

```bash
go get github.com/janmz/ssh-commands
```

Import:

```go
import sshcommands "github.com/janmz/ssh-commands"
```

## Quick Start

```go
opts := &sshcommands.Opts{
    Host:    "example.com",
    Port:    22,
    User:    "deploy",
    KeyFile: "/home/user/.ssh/id_ed25519",
    HostKey: "ssh-ed25519 AAAAC3...", // or path to known_hosts
}

localFiles := []sshcommands.LocalFile{
    {Name: "file.zip", Path: "/local/file.zip", ModTime: time.Now(), Size: 1024},
}
err := sshcommands.Sync(opts, localFiles, "/remote/dir", "", nil)
```

Use at least `KeyFile` or `Password` for authentication. `HostKey` is required
for verified connections (file path or inline key line; multiple keys separated
by ` || `).

## API Overview

| Function | Description |
| --- | --- |
| `Sync` | Upload missing/newer files; delete remote files not in local list |
| `List` | List non-directory entries in a remote directory |
| `Delete` | Remove given file names from a remote directory |
| `Download` | Download files matching a pattern (`*`, `?` wildcards) |
| `DownloadWithOptions` | `Download` with size limit / legacy decryption opt-in |
| `ValidDownloadPattern` | Validate a download pattern before use |
| `ValidRemoteFileName` | Reject `.`, path components, `..` and control characters |
| `FetchServerHostKey` | Fetch server host key without verification (setup) |
| `HostKeyAlreadyPresent` | Check whether a key line is already configured |
| `DialKnownHosts` | Connect using an OpenSSH `known_hosts` file |
| `DialWithHostKeyCallback` | Connect with a custom host key callback |
| `NewSFTPClient` | Open SSH + SFTP clients (lower-level access) |
| `MkdirAllRemote` | Create remote directories recursively |
| `UploadFileIfNewer` | Upload a single file when missing, newer or of different size |
| `FormatKnownHostsHostToken` | Build host token for `known_hosts` entries |
| `AppendKnownHostsLine` | Append a host token and key line to a file |
| `AppendServerHostKey` | Fetch and append server key when the host is unknown |

All operations accept an optional `Logger` (`Info`, `Warn`). Pass `nil` to
disable logging.

## Usage

### Connection options

Build `Opts` with SSH connection parameters:

```go
opts := &sshcommands.Opts{
    Host:     "example.com",
    Port:     22,
    User:     "deploy",
    KeyFile:  "/home/user/.ssh/id_ed25519",  // or Password: "<your-password>"
    KeyPassphrase: "<passphrase>",            // only for an encrypted KeyFile
    HostKey:  "ssh-ed25519 AAAAC3...",        // or path to known_hosts file
    Timeout:  10 * time.Second,               // optional; 0 => 30s (DefaultSSHTimeout)
    KeepAliveInterval: 15 * time.Second,      // optional; 0 => 15s, negative => off
}
```

- `Host` may be a host name, IPv4 or IPv6 address (without brackets); `Port`
  0 means 22, `User` is required.
- `Timeout` limits TCP connect, SSH handshake and SFTP start; running
  transfers are not cut off. A hanging server is detected by SSH keepalives
  instead: after `KeepAliveMaxMissed` (default 3) unanswered requests the
  connection is closed and pending operations fail.
- An encrypted private key needs `KeyPassphrase`. On Unix a warning is logged
  when the key file is readable by group or others.
- An empty `Host` makes every operation return `ErrRemoteNotConfigured`
  (check with `errors.Is` if the remote is optional). An empty remote
  directory is rejected.
- `HostKey` inline entries may be `key-type base64 [comment]` or full
  `known_hosts` lines; a value without spaces is treated as a file path
  ("host key file not found" when it does not exist).

`Sync`, `Delete` and `Download` reject (or skip) file names that are `.`,
contain path components, `..` or control characters, to prevent path
traversal. On Windows, `Download` additionally skips names that cannot be
created locally (`CON`, `NUL.txt`, trailing dot/space, `<>:"|?*`). On a host
key mismatch only the SHA-256 fingerprint of the server key is logged; names
from the server are logged quoted, local paths only by their base name.

### Sync (upload and prune)

Upload local files that are missing on the remote, have a different size or
are newer (compared in whole seconds); remove remote files that are not in the
local list. Optional AES password for encryption.

```go
localFiles := []sshcommands.LocalFile{
    {Name: "file.zip", Path: "/local/file.zip", ModTime: t, Size: 1024},
}
err := sshcommands.Sync(opts, localFiles, "/remote/dir", "", log)
```

- All names are checked (path traversal, duplicates) before connecting.
- An empty `localFiles` list is rejected, since it would delete every remote
  file; use `Delete` for that.
- Uploads go to a temporary name (`.sshcmd-upload-…`) and are renamed when
  complete, so an aborted upload never looks like a finished file; leftovers
  are removed by the next `Sync`. The remote mtime is set to `LocalFile.ModTime`.

### List

```go
entries, err := sshcommands.List(opts, "/remote/dir", log)
// entries: []RemoteEntry{Name, ModTime, Size}
```

### Delete

```go
err := sshcommands.Delete(opts, "/remote/dir", []string{"old.zip"}, log)
```

All names are validated first (nothing is deleted if one is invalid); failed
removals are collected and returned together.

### Download

```go
if !sshcommands.ValidDownloadPattern("backup_*.zip") {
    // handle invalid pattern
}
paths, err := sshcommands.Download(opts, "backup_*.zip", "/local/dir",
    "/remote/dir", aesPassword, log)
// paths: []string of written local paths
```

`destDir` is required. Existing local files are never overwritten: the file is
saved as `<name>.lokal`, then `<name>.lokal.2`, …. Data is written to a
temporary file in `destDir` first, so a failed download (e.g. wrong AES
password) leaves nothing behind.

With an AES password every file must be encrypted in the current format;
otherwise `ErrNotEncrypted` is returned. `DownloadWithOptions` adds a per-file
size limit and the opt-in for files written before 1.1.0:

```go
paths, err := sshcommands.DownloadWithOptions(opts, "backup_*.zip", "/local/dir",
    "/remote/dir", aesPassword, sshcommands.DownloadOptions{
        MaxSize:               2 << 30, // bytes per file; 0 = unlimited (ErrDownloadTooLarge)
        AllowLegacyDecryption: false,   // true only to migrate old backups
    }, log)
```

### Fetch server host key

Connect without host key verification and return the server’s key line (e.g. for
initial setup). The handshake is aborted right after the key exchange, so no
credentials are sent; only `Host` and `Port` are needed:

```go
keyLine, err := sshcommands.FetchServerHostKey(opts)
// keyLine: "ssh-ed25519 AAAAC3..."
```

### Host key already present

```go
ok, err := sshcommands.HostKeyAlreadyPresent(currentHostKeyValue, newKeyLine)
```

The check ignores host names; `@revoked` and `@cert-authority` lines never
count as present.

### Connect via known_hosts file

```go
client, err := sshcommands.DialKnownHosts(opts, sshcommands.KnownHostsOptions{
    Path:            "/home/user/.ssh/known_hosts",
    FetchHostKey:    true,  // fetch server key and append when the host is unknown
    TrustOnMismatch: false, // development only, see below
}, log)
defer client.Close()
```

`FetchHostKey` creates the file when needed and adds the server key only when
the file does not know the host yet (trust on first use, no credentials sent).
Without it, `DialKnownHosts` returns an error when the file does not exist.

A changed key of a known host is a mismatch. **`TrustOnMismatch` is meant for
development environments only:** it accepts the key presented in the failing
connection, replaces the host's previous `known_hosts` entries with it (other
hosts, comments and `@revoked` lines are kept), logs the new fingerprint as a
warning and retries once. This disables MITM protection for changed keys.

`AppendKnownHostsLine` accepts only tokens naming exactly one host (`host`,
`[host]:port` or a hashed token) and writes the key as `key-type base64`.

### Upload a single file

```go
client, err := sshcommands.DialKnownHosts(opts, kh, log)
// ...
err = sshcommands.MkdirAllRemote(client, "/remote/dir", log)
err = sshcommands.UploadFileIfNewer(client, "/local/file.zip",
    "/remote/dir/file.zip", log)
```

### Lower-level SFTP access

```go
sftpClient, sshClient, err := sshcommands.NewSFTPClient(opts, log)
defer sshClient.Close()
defer sftpClient.Close()
```

## Encryption

When `aesPassword` is non-empty (surrounding whitespace is ignored), `Sync`
encrypts and `Download` decrypts. Format (version 3, since 1.1.0):

```
"SSHC" | 0x03 | iterations(uint32) | salt(16) | nonce(16) | AES-256-CTR ciphertext | HMAC-SHA256(32)
```

PBKDF2-SHA256 (600,000 iterations, stored in the header; files with fewer than
100,000 or more than 10,000,000 are rejected) derives the AES and HMAC keys.
The HMAC covers header, remote file name and ciphertext: a wrong password, a
modified file or a file renamed/swapped on the server is reported as
`ErrDecryptIntegrity`. Renaming an encrypted file on the server therefore makes
it undecryptable under the new name. `EncryptionOverhead` (73 bytes) is the
size difference to the plain file.

Files in the legacy format (salt | nonce | ciphertext, without integrity check,
written before 1.1.0) are only decrypted with
`DownloadOptions.AllowLegacyDecryption` (a warning is logged). Enable it only
to migrate old backups: without a MAC an attacker with write access to the
server could modify such files. The next `Sync` uploads them again in the new
format, because their size no longer matches.

## Development

```bash
git config core.hooksPath .githooks   # once: pre-commit hook
sh scripts/check.sh                   # gofmt, vet, golangci-lint, tests, doc pairs
go test -run TestSyncDownloadRoundTrip -v ./...
```

The tests start an in-process SSH/SFTP server, so no external server is needed.

See [CONTRIBUTING.md](CONTRIBUTING.md) for pull request guidelines.

## Security

Do not commit SSH keys, passwords, or real host names. See
[SECURITY.md](SECURITY.md) for reporting vulnerabilities and design notes.

## Related Documentation

- [Changelog](Changelog.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)

## License

MIT License — Copyright (c) Jan Neuhaus / VAYA Consulting. See [LICENSE](LICENSE).
