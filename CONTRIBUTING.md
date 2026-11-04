# Contributing to ssh-commands

Thanks for your interest in contributing!

[🇩🇪 Deutsche Version](CONTRIBUTING.de.md)

## Development

- Go version: see `go.mod` (currently Go 1.26+).
- Install [golangci-lint](https://golangci-lint.run/) v2.14.0 and enable the
  pre-commit hook once per clone:

```bash
git config core.hooksPath .githooks
```

- The hook and CI run the same script (gofmt, `go vet`, golangci-lint, tests,
  EN/DE documentation pairs):

```bash
sh scripts/check.sh
go test -run TestNeedsUpload -v ./...   # single test
```

Optional vulnerability scan (version pinned as in CI):

```bash
go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
govulncheck ./...
```

CI runs the checks on Ubuntu, Windows, and macOS. Tool versions are pinned in
`.github/workflows/ci.yml`; only adopt releases that are at least 14 days old.

## Pull Requests

1. Fork the repo and create a feature branch.
2. Add or update tests for behaviour changes.
3. Ensure `go vet ./...` and `go test ./...` pass.
4. Update [Changelog.md](Changelog.md) and bump `version.go` when applicable.
5. Update [README.md](README.md) and [README.de.md](README.de.md) if the public
   API changes.
6. Submit a PR describing your changes and motivation.

## Commit Messages

- Use clear, descriptive messages.
- Reference issues where relevant (e.g. `Fixes #123`).

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the same
terms as the project ([LICENSE](LICENSE), MIT).

## Code of Conduct

By participating, you agree to abide by the
[Code of Conduct](CODE_OF_CONDUCT.md).
