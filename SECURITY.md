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
  initial setup only.
- **TrustOnMismatch:** When enabled, a host key mismatch updates `known_hosts`
  and retries once. Use only in controlled environments.
- **AES encryption:** Optional upload/download encryption uses a caller-supplied
  password (PBKDF2 + AES-256-CTR). It protects file contents in transit/at rest
  on the server but is not a substitute for SSH transport security.

## Donationware Note

This project is offered as **donationware** for
[CFI Kinderhilfe](https://cfi-kinderhilfe.de/jetzt-spenden/?q=VAYASSH).
Donations do not replace responsible disclosure of security issues.
