# ssh-commands

Go library for SSH/SFTP operations with a parameter-based API: upload (sync),
list, delete, download, and fetch server host keys. No config struct dependency;
all options are passed as parameters. Optional AES-256-CTR encryption for
upload/download.

[![Go Reference](https://pkg.go.dev/badge/github.com/janmz/ssh-commands.svg)](https://pkg.go.dev/github.com/janmz/ssh-commands)
[![Go Report Card](https://goreportcard.com/badge/github.com/janmz/ssh-commands)](https://goreportcard.com/report/github.com/janmz/ssh-commands)
[![CI](https://github.com/janmz/ssh-commands/actions/workflows/ci.yml/badge.svg)](https://github.com/janmz/ssh-commands/actions/workflows/ci.yml)

[🇩🇪 Deutsche Version](README.de.md)

**Donationware for [CFI Kinderhilfe](https://cfi-kinderhilfe.de/jetzt-spenden/?q=VAYASSH).**
License: MIT with attribution (see [LICENSE](LICENSE)).

## Requirements

- Go 1.25 or later (see `go.mod`)

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
    HostKey: "ed25519 AAAAC3...", // or path to known_hosts
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
| `ValidDownloadPattern` | Validate a download pattern before use |
| `FetchServerHostKey` | Fetch server host key without verification (setup) |
| `HostKeyAlreadyPresent` | Check whether a key line is already configured |
| `DialKnownHosts` | Connect using an OpenSSH `known_hosts` file |
| `DialWithHostKeyCallback` | Connect with a custom host key callback |
| `NewSFTPClient` | Open SSH + SFTP clients (lower-level access) |
| `MkdirAllRemote` | Create remote directories recursively |
| `UploadFileIfNewer` | Upload a single file when local is newer |
| `FormatKnownHostsHostToken` | Build host token for `known_hosts` entries |
| `AppendKnownHostsLine` | Append a host token and key line to a file |
| `AppendServerHostKey` | Fetch and append server key when missing |

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
    HostKey:  "ed25519 AAAAC3...",            // or path to known_hosts file
}
```

### Sync (upload and prune)

Upload local files that are missing or newer on the remote; remove remote files
that are not in the local list. Optional AES password for encryption.

```go
localFiles := []sshcommands.LocalFile{
    {Name: "file.zip", Path: "/local/file.zip", ModTime: t, Size: 1024},
}
err := sshcommands.Sync(opts, localFiles, "/remote/dir", "", log)
```

### List

```go
entries, err := sshcommands.List(opts, "/remote/dir", log)
// entries: []RemoteEntry{Name, ModTime, Size}
```

### Delete

```go
err := sshcommands.Delete(opts, "/remote/dir", []string{"old.zip"}, log)
```

### Download

```go
if !sshcommands.ValidDownloadPattern("backup_*.zip") {
    // handle invalid pattern
}
paths, err := sshcommands.Download(opts, "backup_*.zip", "/local/dir",
    "/remote/dir", aesPassword, log)
// paths: []string of written local paths
```

### Fetch server host key

Connect without host key verification and return the server’s key line (e.g. for
initial setup):

```go
keyLine, err := sshcommands.FetchServerHostKey(opts)
// keyLine: "ed25519 AAAAC3..."
```

### Host key already present

```go
ok, err := sshcommands.HostKeyAlreadyPresent(currentHostKeyValue, newKeyLine)
```

### Connect via known_hosts file

```go
client, err := sshcommands.DialKnownHosts(opts, sshcommands.KnownHostsOptions{
    Path:            "/home/user/.ssh/known_hosts",
    FetchHostKey:    true,  // fetch server key and append when missing
    TrustOnMismatch: true,  // on mismatch, append current key and retry once
}, log)
defer client.Close()
```

`FetchHostKey` creates the file when needed. Without it, `DialKnownHosts`
returns an error when the file does not exist.

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

When `aesPassword` is non-empty, `Sync` encrypts and `Download` decrypts using
AES-256-CTR with PBKDF2-derived keys (salt + nonce prefix). Format is
compatible with streams written by this package.

## Development

```bash
go vet ./...
go test ./... -v
```

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
