# Security Policy

[🇩🇪 Deutsche Version](SECURITY.de.md)

## Supported Versions

Security updates are provided for the **latest release** and the `main` branch.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security problems.

Report them privately to `jan@vaya-consulting.de`. Include:

- A short description of the issue and its impact
- Steps to reproduce (if possible)
- Affected versions or environment (Go version, OS), if known

We aim to acknowledge reports within 72 hours and coordinate a fix and
responsible disclosure.

## Security Considerations

- **SSH credentials:** `Opts.Password` and `Opts.KeyFile` are passed in plain
  form. Callers must protect config files, environment variables, and logs.
- **Host key verification:** Use `HostKey` or `DialKnownHosts` for verified
  connections. `FetchServerHostKey` intentionally skips verification for
  initial setup only; it sends no credentials.
- **TrustOnMismatch:** Development only. A host key mismatch replaces the
  host's `known_hosts` entries with the presented key (fingerprint logged as
  warning) and retries once, which disables MITM protection for changed keys.
- **AES encryption:** Optional upload/download encryption uses a caller-supplied
  password (PBKDF2-SHA256 with 600,000 iterations, AES-256-CTR, HMAC-SHA256 over
  header, file name and ciphertext). It protects file contents at rest on the
  server but is not a substitute for SSH transport security. The legacy format
  without MAC is only read with `DownloadOptions.AllowLegacyDecryption`.
- **Timeouts:** `Opts.Timeout` bounds connect, handshake and SFTP start; SSH
  keepalives close connections to hanging servers.

## Donationware Note

This project is offered as **donationware** for
[CFI Kinderhilfe](https://cfi-kinderhilfe.de/jetzt-spenden/?q=VAYASSH).
Donations do not replace responsible disclosure of security issues.
