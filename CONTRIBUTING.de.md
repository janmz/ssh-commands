# Mitwirkung an ssh-commands

Vielen Dank für Ihr Interesse an diesem Projekt!

[🇬🇧 English version](CONTRIBUTING.md)

## Entwicklung

- Go-Version: siehe `go.mod` (derzeit Go 1.26+).
- [golangci-lint](https://golangci-lint.run/) v2.14.0 installieren und den
  Pre-Commit-Hook einmalig pro Klon aktivieren:

```bash
git config core.hooksPath .githooks
```

- Hook und CI nutzen dasselbe Skript (gofmt, `go vet`, golangci-lint, Tests,
  EN/DE-Dokumentpaare):

```bash
sh scripts/check.sh
go test -run TestNeedsUpload -v ./...   # einzelner Test
```

Optional Schwachstellen-Scan (Version wie in der CI gepinnt):

```bash
go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
govulncheck ./...
```

Die CI führt die Prüfungen auf Ubuntu, Windows und macOS aus. Tool-Versionen
sind in `.github/workflows/ci.yml` gepinnt; nur Releases übernehmen, die
mindestens 14 Tage alt sind.

## Pull Requests

1. Repository forken und einen Feature-Branch anlegen.
2. Bei Verhaltensänderungen Tests ergänzen oder anpassen.
3. Sicherstellen, dass `go vet ./...` und `go test ./...` grün sind.
4. [Changelog.md](Changelog.md) aktualisieren und `version.go` anpassen, wenn
   nötig.
5. [README.md](README.md) und [README.de.md](README.de.md) bei API-Änderungen
   mitpflegen.
6. PR mit Beschreibung der Änderung und Motivation einreichen.

## Commit-Nachrichten

- Klare, aussagekräftige Nachrichten verwenden.
- Issues referenzieren, wo sinnvoll (z. B. `Fixes #123`).

## Sicherheit

Schwachstellen bitte vertraulich melden; siehe [SECURITY.de.md](SECURITY.de.md).

## Lizenz

Mit Ihrem Beitrag erklären Sie sich damit einverstanden, dass er unter den
gleichen Bedingungen wie das Projekt ([LICENSE](LICENSE), MIT) lizenziert wird.

## Verhaltenskodex

Mit der Teilnahme stimmen Sie dem
[Code of Conduct](CODE_OF_CONDUCT.md) zu.
