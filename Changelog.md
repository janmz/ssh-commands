# Changelog

All notable changes to this project are documented here.

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
