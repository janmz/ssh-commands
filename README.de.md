# ssh-commands

Go-Bibliothek für SSH-/SFTP-Operationen mit parameterbasierter API: Upload
(Sync), Auflisten, Löschen, Download und Abruf des Server-Host-Keys. Keine
Abhängigkeit von einer Config-Struktur; alle Optionen werden als Parameter
übergeben. Optionale authentifizierte Verschlüsselung (AES-256-CTR +
HMAC-SHA256) für Upload/Download.

[![Go Reference](https://pkg.go.dev/badge/github.com/janmz/ssh-commands.svg)](https://pkg.go.dev/github.com/janmz/ssh-commands)
[![Go Report Card](https://goreportcard.com/badge/github.com/janmz/ssh-commands)](https://goreportcard.com/report/github.com/janmz/ssh-commands)
[![CI](https://github.com/janmz/ssh-commands/actions/workflows/ci.yml/badge.svg)](https://github.com/janmz/ssh-commands/actions/workflows/ci.yml)

[🇬🇧 English version](README.md)

**Donationware für die
[CFI Kinderhilfe](https://cfi-kinderhilfe.de/jetzt-spenden/?q=VAYASSH).**
Lizenz: MIT mit Namensnennung (siehe [LICENSE](LICENSE)).

## Voraussetzungen

- Go 1.26 oder neuer (siehe `go.mod`)

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
    HostKey: "ssh-ed25519 AAAAC3...", // oder Pfad zu known_hosts
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
| `DownloadWithOptions` | `Download` mit Größenlimit / Opt-in für Altformat |
| `ValidDownloadPattern` | Download-Muster vor Verwendung prüfen |
| `ValidRemoteFileName` | `.`, Pfadanteile, `..` und Steuerzeichen ablehnen |
| `FetchServerHostKey` | Server-Host-Key ohne Prüfung abrufen (Einrichtung) |
| `HostKeyAlreadyPresent` | Prüfen, ob ein Key bereits konfiguriert ist |
| `DialKnownHosts` | Verbindung über OpenSSH-`known_hosts`-Datei |
| `DialWithHostKeyCallback` | Verbindung mit eigenem Host-Key-Callback |
| `NewSFTPClient` | SSH- und SFTP-Clients öffnen (Low-Level-Zugriff) |
| `MkdirAllRemote` | Remote-Verzeichnisse rekursiv anlegen |
| `UploadFileIfNewer` | Einzelne Datei hochladen, wenn fehlend, neuer oder andere Größe |
| `FormatKnownHostsHostToken` | Host-Token für `known_hosts`-Einträge erzeugen |
| `AppendKnownHostsLine` | Host-Token und Key-Zeile an Datei anhängen |
| `AppendServerHostKey` | Server-Key holen und anhängen, wenn der Host unbekannt ist |

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
    KeyPassphrase: "<Passphrase>",            // nur für verschlüsseltes KeyFile
    HostKey:  "ssh-ed25519 AAAAC3...",        // oder Pfad zu known_hosts
    Timeout:  10 * time.Second,               // optional; 0 => 30s (DefaultSSHTimeout)
    KeepAliveInterval: 15 * time.Second,      // optional; 0 => 15s, negativ => aus
}
```

- `Host` darf ein Hostname, eine IPv4- oder IPv6-Adresse (ohne Klammern) sein;
  `Port` 0 bedeutet 22, `User` ist Pflicht.
- `Timeout` begrenzt TCP-Verbindungsaufbau, SSH-Handshake und SFTP-Start;
  laufende Übertragungen werden nicht abgebrochen. Einen hängenden Server
  erkennen stattdessen SSH-Keepalives: Nach `KeepAliveMaxMissed` (Standard 3)
  unbeantworteten Anfragen wird die Verbindung geschlossen, laufende
  Operationen schlagen fehl.
- Ein verschlüsselter privater Schlüssel braucht `KeyPassphrase`. Unter Unix
  wird gewarnt, wenn die Schlüsseldatei für Gruppe oder andere lesbar ist.
- Ein leerer `Host` führt bei jeder Funktion zu `ErrRemoteNotConfigured`
  (mit `errors.Is` prüfen, falls der Server optional ist). Ein leeres
  Remote-Verzeichnis wird abgelehnt.
- Inline-Einträge in `HostKey` dürfen `key-type base64 [Kommentar]` oder
  vollständige `known_hosts`-Zeilen sein; ein Wert ohne Leerzeichen gilt als
  Dateipfad („host key file not found“, wenn er nicht existiert).

`Sync`, `Delete` und `Download` lehnen Dateinamen ab bzw. überspringen sie, die
`.` sind oder Pfadanteile, `..` oder Steuerzeichen enthalten (Schutz vor
Path-Traversal). Unter Windows überspringt `Download` zusätzlich Namen, die
lokal nicht anlegbar sind (`CON`, `NUL.txt`, Punkt/Leerzeichen am Ende,
`<>:"|?*`). Bei Host-Key-Abweichung wird nur der SHA-256-Fingerprint des
Server-Keys geloggt; Namen vom Server werden in Anführungszeichen, lokale Pfade
nur mit Dateinamen geloggt.

### Sync (Hochladen und Aufräumen)

Lokale Dateien hochladen, die auf dem Server fehlen, eine andere Größe haben
oder neuer sind (Vergleich in ganzen Sekunden); Remote-Dateien löschen, die
nicht in der lokalen Liste sind. Optional AES-Passwort für Verschlüsselung.

```go
localFiles := []sshcommands.LocalFile{
    {Name: "file.zip", Path: "/lokal/file.zip", ModTime: t, Size: 1024},
}
err := sshcommands.Sync(opts, localFiles, "/remote/dir", "", log)
```

- Alle Namen werden vor dem Verbinden geprüft (Path-Traversal, Duplikate).
- Eine leere `localFiles`-Liste wird abgelehnt, da sie alle Remote-Dateien
  löschen würde; dafür `Delete` verwenden.
- Uploads gehen zuerst an einen temporären Namen (`.sshcmd-upload-…`) und werden
  nach Abschluss umbenannt, ein abgebrochener Upload sieht also nie wie eine
  fertige Datei aus; Reste entfernt der nächste `Sync`. Die Remote-mtime wird
  auf `LocalFile.ModTime` gesetzt.

### Auflisten

```go
entries, err := sshcommands.List(opts, "/remote/dir", log)
// entries: []RemoteEntry{Name, ModTime, Size}
```

### Löschen

```go
err := sshcommands.Delete(opts, "/remote/dir", []string{"old.zip"}, log)
```

Alle Namen werden vorab geprüft (bei einem ungültigen Namen wird nichts
gelöscht); fehlgeschlagene Löschungen werden gesammelt zurückgegeben.

### Download

```go
if !sshcommands.ValidDownloadPattern("backup_*.zip") {
    // ungültiges Muster behandeln
}
paths, err := sshcommands.Download(opts, "backup_*.zip", "/lokal/dir",
    "/remote/dir", aesPassword, log)
// paths: []string der geschriebenen lokalen Pfade
```

`destDir` ist Pflicht. Vorhandene lokale Dateien werden nie überschrieben: Die
Datei wird als `<name>.lokal`, dann `<name>.lokal.2`, … gespeichert. Die Daten
landen zuerst in einer temporären Datei in `destDir`; ein fehlgeschlagener
Download (z. B. falsches AES-Passwort) hinterlässt nichts.

Mit AES-Passwort muss jede Datei im aktuellen Format verschlüsselt sein, sonst
wird `ErrNotEncrypted` geliefert. `DownloadWithOptions` ergänzt ein
Größenlimit pro Datei und das Opt-in für Dateien von vor 1.1.0:

```go
paths, err := sshcommands.DownloadWithOptions(opts, "backup_*.zip", "/lokal/dir",
    "/remote/dir", aesPassword, sshcommands.DownloadOptions{
        MaxSize:               2 << 30, // Byte pro Datei; 0 = unbegrenzt (ErrDownloadTooLarge)
        AllowLegacyDecryption: false,   // true nur zur Migration alter Backups
    }, log)
```

### Server-Host-Key abrufen

Ohne Host-Key-Prüfung verbinden und die Key-Zeile des Servers zurückgeben
(z. B. für erstmalige Einrichtung). Der Handshake wird direkt nach dem
Schlüsselaustausch abgebrochen, es werden keine Zugangsdaten gesendet; nur
`Host` und `Port` sind nötig:

```go
keyLine, err := sshcommands.FetchServerHostKey(opts)
// keyLine: "ssh-ed25519 AAAAC3..."
```

### Host-Key bereits vorhanden

```go
ok, err := sshcommands.HostKeyAlreadyPresent(currentHostKeyValue, newKeyLine)
```

Die Prüfung ignoriert Hostnamen; `@revoked`- und `@cert-authority`-Zeilen gelten
nie als vorhanden.

### Verbindung über known_hosts-Datei

```go
client, err := sshcommands.DialKnownHosts(opts, sshcommands.KnownHostsOptions{
    Path:            "/home/user/.ssh/known_hosts",
    FetchHostKey:    true,  // Server-Key holen und anhängen, wenn Host unbekannt
    TrustOnMismatch: false, // nur für Entwicklung, siehe unten
}, log)
defer client.Close()
```

`FetchHostKey` legt die Datei bei Bedarf an und ergänzt den Server-Key nur,
wenn die Datei den Host noch nicht kennt (Trust on First Use, ohne
Zugangsdaten). Ohne `FetchHostKey` liefert `DialKnownHosts` einen Fehler,
wenn die Datei fehlt.

Ein geänderter Key eines bekannten Hosts ist ein Mismatch. **`TrustOnMismatch`
ist nur für Entwicklungsumgebungen gedacht:** Die Option übernimmt den Key der
fehlgeschlagenen Verbindung, ersetzt damit die bisherigen `known_hosts`-Einträge
des Hosts (andere Hosts, Kommentare und `@revoked`-Zeilen bleiben erhalten),
loggt den neuen Fingerprint als Warnung und verbindet einmal erneut. Damit ist
der MITM-Schutz für geänderte Keys aufgehoben.

`AppendKnownHostsLine` akzeptiert nur Tokens für genau einen Host (`host`,
`[host]:port` oder gehashtes Token) und schreibt den Key als `key-type base64`.

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

Wenn `aesPassword` nicht leer ist (Leerzeichen am Rand werden ignoriert),
verschlüsselt `Sync` und entschlüsselt `Download`. Format (Version 3, seit
1.1.0):

```
"SSHC" | 0x03 | Iterationen(uint32) | Salt(16) | Nonce(16) | AES-256-CTR-Chiffrat | HMAC-SHA256(32)
```

PBKDF2-SHA256 (600.000 Iterationen, im Header gespeichert; Dateien mit weniger
als 100.000 oder mehr als 10.000.000 werden abgelehnt) leitet AES- und
HMAC-Schlüssel ab. Der HMAC umfasst Header, Remote-Dateinamen und Chiffrat: Ein
falsches Passwort, eine veränderte oder auf dem Server umbenannte/vertauschte
Datei wird als `ErrDecryptIntegrity` gemeldet. Eine auf dem Server umbenannte
verschlüsselte Datei lässt sich unter dem neuen Namen daher nicht mehr
entschlüsseln. `EncryptionOverhead` (73 Byte) ist der Größenunterschied zur
unverschlüsselten Datei.

Dateien im Altformat (Salt | Nonce | Chiffrat, ohne Integritätsprüfung, vor
1.1.0 geschrieben) werden nur mit `DownloadOptions.AllowLegacyDecryption`
entschlüsselt (mit Warnung). Nur zur Migration alter Backups aktivieren: Ohne
MAC könnte ein Angreifer mit Schreibzugriff auf den Server solche Dateien
verändern. Der nächste `Sync` lädt sie im neuen Format erneut hoch, weil ihre
Größe nicht mehr passt.

## Entwicklung

```bash
git config core.hooksPath .githooks   # einmalig: Pre-Commit-Hook
sh scripts/check.sh                   # gofmt, vet, golangci-lint, Tests, Doku-Paare
go test -run TestSyncDownloadRoundTrip -v ./...
```

Die Tests starten einen SSH/SFTP-Server im Prozess, ein externer Server ist
nicht nötig.

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
