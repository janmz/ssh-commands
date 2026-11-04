# Sicherheitsrichtlinie

[🇬🇧 English version](SECURITY.md)

## Unterstützte Versionen

Sicherheitsupdates erhalten die **aktuellste Veröffentlichung** und der Branch
`main`.

## Schwachstelle melden

Bitte **kein** öffentliches GitHub-Issue für Sicherheitsprobleme.

Melden Sie diese vertraulich an `jan@vaya-consulting.de`. Bitte angeben:

- Kurze Beschreibung des Problems und der Auswirkung
- Schritte zur Reproduktion (falls möglich)
- Betroffene Versionen oder Umgebung (Go-Version, OS), falls bekannt

Wir bestätigen Meldungen in der Regel innerhalb von 72 Stunden und koordinieren
Behebung und verantwortungsvolle Veröffentlichung.

## Sicherheitshinweise

- **SSH-Zugangsdaten:** `Opts.Password` und `Opts.KeyFile` werden im Klartext
  übergeben. Aufrufer müssen Konfigurationsdateien, Umgebungsvariablen und Logs
  schützen.
- **Host-Key-Prüfung:** Für verifizierte Verbindungen `HostKey` oder
  `DialKnownHosts` verwenden. `FetchServerHostKey` überspringt die Prüfung
  bewusst nur für die Ersteinrichtung und sendet keine Zugangsdaten.
- **TrustOnMismatch:** Nur für Entwicklung. Bei einem Mismatch werden die
  `known_hosts`-Einträge des Hosts durch den präsentierten Key ersetzt
  (Fingerprint als Warnung geloggt) und einmal erneut verbunden; der
  MITM-Schutz für geänderte Keys ist damit aufgehoben.
- **AES-Verschlüsselung:** Optionale Upload-/Download-Verschlüsselung nutzt ein
  vom Aufrufer übergebenes Passwort (PBKDF2-SHA256 mit 600.000 Iterationen,
  AES-256-CTR, HMAC-SHA256 über Header, Dateinamen und Chiffrat). Sie schützt
  Dateiinhalte bei der Speicherung auf dem Server, ersetzt aber keine
  SSH-Transportsicherheit. Das Altformat ohne MAC wird nur mit
  `DownloadOptions.AllowLegacyDecryption` gelesen.
- **Timeouts:** `Opts.Timeout` begrenzt Verbindungsaufbau, Handshake und
  SFTP-Start; SSH-Keepalives schließen Verbindungen zu hängenden Servern.

## Hinweis zur Donationware

Dieses Projekt wird als **Donationware** für die
[CFI Kinderhilfe](https://cfi-kinderhilfe.de/jetzt-spenden/?q=VAYASSH)
angeboten. Spenden ersetzen keine verantwortungsvolle Meldung von
Sicherheitsproblemen.
