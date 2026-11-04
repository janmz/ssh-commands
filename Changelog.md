# Changelog

All notable changes to this project are documented here.

## [1.1.0] – 2026-11-04 12:24:43

Release combining the previously unreleased work listed below as 0.3.0
(code review) and 0.3.1 (security audit); neither was published separately.
The version continues after v1.0.1 of the former `janmz/sshcommands`
repository. References to "before 0.3.0" in older notes mean files written by
versions up to 0.2.5.

### Changed

- README (EN/DE): version references point to 1.1.0.

## [0.3.1] – 2026-11-04 11:06:36 (unreleased, part of 1.1.0)

Implements all 14 findings of the security audit of 2026-11-04
(`securityreport.md`, H1–H2, M1–M4, L1–L8).

### Security

- **H1 – legacy downgrade:** files without the current header are no longer
  decrypted by default; `Download` with an AES password returns
  `ErrNotEncrypted`. The legacy format is only read with
  `DownloadOptions.AllowLegacyDecryption` (new `DownloadWithOptions`). The
  current key derivation differs from the legacy one, so a stripped header
  cannot be used for targeted bit flips even with the opt-in.
- **L2 – encryption format v3:** `"SSHC" | 0x03 | iterations | salt | nonce |
  ciphertext | HMAC`; PBKDF2 with 600,000 iterations (stored in the header,
  accepted range 100,000–10,000,000); the HMAC also binds the remote file name
  (swapped/renamed files are detected). `EncryptionOverhead` is now 73. Format
  v2 of the unreleased 0.3.0 is not supported.
- **H2 – dependencies:** `golang.org/x/crypto` v0.52.0 → v0.58.0
  (GO-2026-6354, GO-2026-6355), `golang.org/x/sys` → v0.49.0.
- **M1 – Go version:** `go.mod` requires Go 1.26; CI tests Go 1.26.x and
  1.27.x.
- **M2 – file names:** `ValidRemoteFileName` rejects `.` and control
  characters; `Download` skips names that cannot be created locally on Windows
  (reserved device names, trailing dot/space, `<>:"|?*`).
- **M3 – TrustOnMismatch:** uses the key of the failing connection itself,
  replaces the host's previous entries atomically (other hosts, comments and
  `@revoked` lines are kept, hashed entries are recognised), logs the new
  fingerprint as warning; documented as development only.
- **M4 – keepalive:** `Opts.KeepAliveInterval` (default 15s, negative =
  off) and `Opts.KeepAliveMaxMissed` (default 3) close connections to hanging
  servers.
- **L1 – known_hosts entries:** `AppendKnownHostsLine` accepts only tokens for
  exactly one host (no `*`, `?`, `!`, `,`, `@`, whitespace) and re-serialises
  the key (options rejected, comment dropped).
- **L3:** an empty `destDir` is rejected.
- **L4:** `DownloadOptions.MaxSize` limits each download (`ErrDownloadTooLarge`),
  also when the server sends more data than announced.
- **L5 – CI:** actions pinned by commit SHA, `permissions: contents: read`,
  `persist-credentials: false`, Dependabot with a 14-day cooldown.
- **L6 – logging:** names from the server are logged with `%q`, local paths
  only by base name.
- **L7:** gosec enabled in golangci-lint.
- **L8 – private keys:** `Opts.KeyPassphrase` for encrypted keys (clear error
  when it is missing); warning on Unix when the key file is readable by group
  or others.

### Changed

- CI uses the built-in cache of `actions/setup-go` instead of a separate cache
  step.
- Duplicate `securityreport.md` entry removed from `.gitignore`.

## [0.3.0] – 2026-11-04 10:39:58 (unreleased, part of 1.1.0)

Implements all 25 findings of the code review (`codereview.md`, CR-1 … CR-25).

### Breaking changes

- **Encryption format v2:** `"SSHC" | 0x02 | salt | nonce | ciphertext |
  HMAC-SHA256`. `EncryptionOverhead` is now 69 (was 32). Legacy files are still
  decrypted (with a warning) and re-uploaded by the next `Sync`. Wrong password
  or tampering → `ErrDecryptIntegrity` (CR-5).
- **Sync** rejects an empty `localFiles` list instead of deleting every remote
  file (CR-11), and an empty `Host` now returns `ErrRemoteNotConfigured`
  instead of `nil` (CR-15).
- **Opts:** `User` is required, `Port` must be 0..65535, remote directories
  must not be empty (CR-15).
- **Delete** returns the collected removal errors (`errors.Join`) instead of
  `nil` (CR-10).
- **Inline `HostKey`:** an unparsable entry is an error naming that entry
  instead of being skipped silently (CR-12).
- **AppendServerHostKey** only adds a key for hosts the file does not know;
  a changed key of a known host is no longer appended silently (CR-8).
- Downloaded files are created with mode 0600.

### Security

- **FetchServerHostKey** aborts the handshake after the key exchange and sends
  no credentials; `DialKnownHosts` with `FetchHostKey` thus no longer exposes
  the password to an unverified server and contacts the server only for unknown
  hosts (CR-1).
- **Timeout** now also covers the SSH handshake and SFTP start, not only the
  TCP connect (CR-14).
- **known_hosts append:** adds a missing trailing newline first and rejects
  CR/LF/NUL and invalid key lines (CR-7).
- **HostKeyAlreadyPresent:** lines with comments are recognised, `@revoked` and
  `@cert-authority` never count as present (CR-8).
- Size limits for private key (1 MiB), known_hosts (16 MiB) and remote
  directory listings (200,000 entries) (CR-17).

### Fixed

- **Aborted uploads:** `Sync` and `UploadFileIfNewer` write to a temporary name
  and rename on completion; the remote mtime is set to the local mtime; the
  upload decision compares size and mtime (in whole seconds) in both modes;
  leftovers are pruned (CR-2, CR-3).
- **AES password** is trimmed identically for `Sync` and `Download` (CR-4).
- **IPv6 hosts** via `net.JoinHostPort` (CR-6).
- **Download** writes to a temporary file, removes it on error and picks a
  free name (`.lokal`, `.lokal.2`, …) atomically (CR-9).
- **Sync** validates all names (incl. duplicates) before connecting (CR-16).
- Write handles are closed explicitly and close errors are returned (CR-13).
- Error messages without duplicate `ssh: ssh:` prefix; host key failures are
  logged as warning with the real cause; mismatch detection via
  `errors.As(*knownhosts.KeyError)` (CR-23).

### Changed

- Auth, port default, address and dial logic centralised (`buildAuthMethods`,
  `Opts.port/addr/validate`, `dialSSH`, `DefaultSSHPort`); one inline host key
  parser (CR-20, CR-21, CR-22).
- Prune uses a name set instead of a nested loop; `UploadFileIfNewer` uses one
  SFTP session (CR-18, CR-19).

### Added

- `ErrRemoteNotConfigured`, `ErrDecryptIntegrity`, `DefaultSSHPort`.
- In-process SSH/SFTP test server with end-to-end tests (Sync, Download,
  Delete, known_hosts, handshake timeout, no credentials on key fetch) and
  table tests for the upload decision and the host key parser (CR-25).
- `scripts/check.sh`, pre-commit hook (`.githooks/pre-commit`),
  `.golangci.yml`, `.gitattributes`; CI pins golangci-lint v2.14.0 and
  govulncheck v1.9.0 (CR-24).

## [0.2.5] – 2026-11-04 10:02:52

### Security

Ported from the former `janmz/sshcommands` repository (v1.0.1):

- **Path traversal:** new `ValidRemoteFileName()`; `Delete` returns an error
  for invalid names, `Download` ignores invalid server names when matching
  wildcards, `Sync` rejects invalid local names and skips invalid remote names
  when pruning. `ValidDownloadPattern` now delegates to it.
- **SSH timeout:** new `Opts.Timeout` and `DefaultSSHTimeout` (30s), used by
  `NewSFTPClient`, `FetchServerHostKey` and `DialWithHostKeyCallback`
  (previously fixed 30s there, none elsewhere).
- **Host key logging:** on mismatch only the SHA-256 fingerprint is logged
  instead of the full public key.

### Added

- Unit tests for `ValidRemoteFileName`, `ValidDownloadPattern` and the timeout
  default.

### Changed

- README (EN/DE): documents `ValidRemoteFileName`, `Opts.Timeout`, path
  traversal protection and fingerprint-only host key logging.
- `.gitignore`: also excludes `CLAUDE.md`, `.claude/`, `securityreport.md` and
  `*.syso`.

## [0.2.4] – 2026-06-24 00:44:59

### Fixed

- **CI:** workflow matrix switched from Go 1.24.x to 1.25.x to match `go.mod`,
  so the CI run works again (commit `2472b51`).

### Changed

- CONTRIBUTING and README (EN/DE): required Go version updated to 1.25+.

## [0.2.3] – 2026-06-24 00:41:50

### Changed

- **Dependencies:** `golang.org/x/crypto` upgraded to v0.52.0 (fixes
  govulncheck findings GO-2026-5013 through GO-2026-5021).
- **Go:** minimum version raised to 1.25; CI uses Go 1.25.x (≥ 1.25.10 for
  stdlib fix GO-2026-4971).

## [0.2.2] – 2026-06-24 00:34:37

### Added

- GitHub documentation set: bilingual README, CONTRIBUTING, SECURITY, Code of
  Conduct, FUNDING, and CI workflow.
- `version.go` with library version and build time.
- `.gitignore` for secrets, IDE, and assistant config files.

### Changed

- README: API overview, quick start, development and security sections, badges.

## [0.2.1] – 2026-06-23 17:14:17

### Fixed

- **Download:** `getOneFile` now uses `streamDecryptDownload` instead of
  duplicating AES decrypt logic (removes unused-function warning).

## [0.2.0] – 2026-06-23 09:52:10

### Added

- **KnownHostsOptions** and **DialKnownHosts:** SSH connections via an OpenSSH
  `known_hosts` file with optional `FetchHostKey` (fetch and append server key)
  and `TrustOnMismatch` (update key and retry once).
- **DialWithHostKeyCallback:** connect with a custom host key callback
  (`opts.HostKey` ignored).
- **FormatKnownHostsHostToken**, **AppendKnownHostsLine**, **AppendServerHostKey:**
  helpers to manage known_hosts entries.
- **MkdirAllRemote**, **UploadFileIfNewer:** single-file SFTP upload without
  deleting other remote files; skips upload when remote is current.
- Unit tests for known_hosts helpers and host key presence checks.

## [0.1.0] – 2026-02-27

### Added

- Initial release. SSH/SFTP library with parameter-based API:
  - **Opts:** Host, Port, User, KeyFile, Password, HostKey.
  - **Sync:** Upload local files (missing/newer), delete remote files not in list;
    optional AES-256-CTR encryption.
  - **List:** List non-directory entries in a remote directory.
  - **Delete:** Remove given file names from remote directory.
  - **Download:** Download by pattern (literal or wildcards); optional decryption.
  - **FetchServerHostKey:** Get server host key without verification (for setup).
  - **HostKeyAlreadyPresent:** Check if a key line is already in configured keys.
- Optional **Logger** interface for progress and host-key mismatch messages.
- No dependency on config structs or i18n; suitable for reuse in other projects.
