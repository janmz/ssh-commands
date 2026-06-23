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
  bewusst nur für die Ersteinrichtung.
- **TrustOnMismatch:** Bei aktivierter Option wird bei einem Mismatch der
  `known_hosts`-Eintrag aktualisiert und einmal erneut verbunden. Nur in
  kontrollierten Umgebungen einsetzen.
- **AES-Verschlüsselung:** Optionale Upload-/Download-Verschlüsselung nutzt ein
  vom Aufrufer übergebenes Passwort (PBKDF2 + AES-256-CTR). Sie schützt
  Dateiinhalte während Übertragung/Speicherung auf dem Server, ersetzt aber
  keine SSH-Transportsicherheit.

## Hinweis zur Donationware

Dieses Projekt wird als **Donationware** für die
[CFI Kinderhilfe](https://cfi-kinderhilfe.de/jetzt-spenden/?q=VAYASSH)
angeboten. Spenden ersetzen keine verantwortungsvolle Meldung von
Sicherheitsproblemen.
