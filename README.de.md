# ssh-commands

Go-Bibliothek für SSH-/SFTP-Operationen mit parameterbasierter API: Upload
(Sync), Auflisten, Löschen, Download und Abruf des Server-Host-Keys. Keine
Abhängigkeit von einer Config-Struktur; alle Optionen werden als Parameter
übergeben. Optionale AES-256-CTR-Verschlüsselung für Upload/Download.

[![Go Reference](https://pkg.go.dev/badge/github.com/janmz/ssh-commands.svg)](https://pkg.go.dev/github.com/janmz/ssh-commands)
[![Go Report Card](https://goreportcard.com/badge/github.com/janmz/ssh-commands)](https://goreportcard.com/report/github.com/janmz/ssh-commands)
[![CI](https://github.com/janmz/ssh-commands/actions/workflows/ci.yml/badge.svg)](https://github.com/janmz/ssh-commands/actions/workflows/ci.yml)

[🇬🇧 English version](README.md)

**Donationware für die
[CFI Kinderhilfe](https://cfi-kinderhilfe.de/jetzt-spenden/?q=VAYASSH).**
Lizenz: MIT mit Namensnennung (siehe [LICENSE](LICENSE)).

## Voraussetzungen

- Go 1.25 oder neuer (siehe `go.mod`)

## Installation

```bash
go get github.com/janmz/ssh-commands
```

Import:

```go
import sshcommands "github.com/janmz/ssh-commands"
```

## Schnellstart

```go
opts := &sshcommands.Opts{
    Host:    "example.com",
    Port:    22,
    User:    "deploy",
    KeyFile: "/home/user/.ssh/id_ed25519",
    HostKey: "ed25519 AAAAC3...", // oder Pfad zu known_hosts
}

localFiles := []sshcommands.LocalFile{
    {Name: "file.zip", Path: "/lokal/file.zip", ModTime: time.Now(), Size: 1024},
}
err := sshcommands.Sync(opts, localFiles, "/remote/dir", "", nil)
```

Mindestens `KeyFile` oder `Password` für die Anmeldung. `HostKey` ist für
verifizierte Verbindungen nötig (Dateipfad oder Inline-Key; mehrere Keys mit
` || ` getrennt).

## API-Übersicht

| Funktion | Beschreibung |
| --- | --- |
| `Sync` | Fehlende/neuere Dateien hochladen; Remote-Dateien außerhalb der Liste löschen |
| `List` | Nicht-Verzeichnis-Einträge in einem Remote-Verzeichnis auflisten |
| `Delete` | Gegebene Dateinamen im Remote-Verzeichnis entfernen |
| `Download` | Dateien nach Muster herunterladen (Wildcards `*`, `?`) |
| `ValidDownloadPattern` | Download-Muster vor Verwendung prüfen |
| `FetchServerHostKey` | Server-Host-Key ohne Prüfung abrufen (Einrichtung) |
| `HostKeyAlreadyPresent` | Prüfen, ob ein Key bereits konfiguriert ist |
| `DialKnownHosts` | Verbindung über OpenSSH-`known_hosts`-Datei |
| `DialWithHostKeyCallback` | Verbindung mit eigenem Host-Key-Callback |
| `NewSFTPClient` | SSH- und SFTP-Clients öffnen (Low-Level-Zugriff) |
| `MkdirAllRemote` | Remote-Verzeichnisse rekursiv anlegen |
| `UploadFileIfNewer` | Einzelne Datei hochladen, wenn lokal neuer |
| `FormatKnownHostsHostToken` | Host-Token für `known_hosts`-Einträge erzeugen |
| `AppendKnownHostsLine` | Host-Token und Key-Zeile an Datei anhängen |
| `AppendServerHostKey` | Server-Key holen und anhängen, wenn fehlend |

Alle Funktionen akzeptieren optional einen `Logger` (`Info`, `Warn`). `nil`
bedeutet kein Logging.

## Verwendung

### Verbindungsoptionen

`Opts` mit SSH-Parametern aufbauen:

```go
opts := &sshcommands.Opts{
    Host:     "example.com",
    Port:     22,
    User:     "deploy",
    KeyFile:  "/home/user/.ssh/id_ed25519",  // oder Password: "<Ihr-Passwort>"
    HostKey:  "ed25519 AAAAC3...",            // oder Pfad zu known_hosts
}
```

### Sync (Hochladen und Aufräumen)

Lokale Dateien hochladen, die fehlen oder neuer sind; Remote-Dateien löschen,
die nicht in der lokalen Liste sind. Optional AES-Passwort für Verschlüsselung.

```go
localFiles := []sshcommands.LocalFile{
    {Name: "file.zip", Path: "/lokal/file.zip", ModTime: t, Size: 1024},
}
err := sshcommands.Sync(opts, localFiles, "/remote/dir", "", log)
```

### Auflisten

```go
entries, err := sshcommands.List(opts, "/remote/dir", log)
// entries: []RemoteEntry{Name, ModTime, Size}
```

### Löschen

```go
err := sshcommands.Delete(opts, "/remote/dir", []string{"old.zip"}, log)
```

### Download

```go
if !sshcommands.ValidDownloadPattern("backup_*.zip") {
    // ungültiges Muster behandeln
}
paths, err := sshcommands.Download(opts, "backup_*.zip", "/lokal/dir",
    "/remote/dir", aesPassword, log)
// paths: []string der geschriebenen lokalen Pfade
```

### Server-Host-Key abrufen

Ohne Host-Key-Prüfung verbinden und die Key-Zeile des Servers zurückgeben
(z. B. für erstmalige Einrichtung):

```go
keyLine, err := sshcommands.FetchServerHostKey(opts)
// keyLine: "ed25519 AAAAC3..."
```

### Host-Key bereits vorhanden

```go
ok, err := sshcommands.HostKeyAlreadyPresent(currentHostKeyValue, newKeyLine)
```

### Verbindung über known_hosts-Datei

```go
client, err := sshcommands.DialKnownHosts(opts, sshcommands.KnownHostsOptions{
    Path:            "/home/user/.ssh/known_hosts",
    FetchHostKey:    true,  // Server-Key holen und anhängen, wenn fehlend
    TrustOnMismatch: true,  // bei Mismatch Key aktualisieren und einmal erneut verbinden
}, log)
defer client.Close()
```

Ohne `FetchHostKey` liefert `DialKnownHosts` einen Fehler, wenn die Datei
fehlt.

### Einzelne Datei hochladen

```go
client, err := sshcommands.DialKnownHosts(opts, kh, log)
// ...
err = sshcommands.MkdirAllRemote(client, "/remote/dir", log)
err = sshcommands.UploadFileIfNewer(client, "/local/file.zip",
    "/remote/dir/file.zip", log)
```

### Low-Level-SFTP-Zugriff

```go
sftpClient, sshClient, err := sshcommands.NewSFTPClient(opts, log)
defer sshClient.Close()
defer sftpClient.Close()
```

## Verschlüsselung

Wenn `aesPassword` nicht leer ist, verschlüsselt `Sync` und entschlüsselt
`Download` mit AES-256-CTR und PBKDF2-abgeleiteten Schlüsseln (Salt+Nonce-
Präfix). Format ist kompatibel mit von diesem Package geschriebenen Streams.

## Entwicklung

```bash
go vet ./...
go test ./... -v
```

Siehe [CONTRIBUTING.de.md](CONTRIBUTING.de.md) für Richtlinien zu Pull Requests.

## Sicherheit

Keine SSH-Keys, Passwörter oder echten Hostnamen ins Repository committen. Siehe
[SECURITY.de.md](SECURITY.de.md) für Meldewege und Hinweise zum Design.

## Weitere Dokumentation

- [Changelog](Changelog.md)
- [Mitwirkung](CONTRIBUTING.de.md)
- [Sicherheitsrichtlinie](SECURITY.de.md)
- [Verhaltenskodex](CODE_OF_CONDUCT.md)

## Lizenz

MIT-Lizenz — Copyright (c) Jan Neuhaus / VAYA Consulting. Siehe [LICENSE](LICENSE).
