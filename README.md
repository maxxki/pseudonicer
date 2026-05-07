MAXXKI PII Pseudonicer v6.0
===========================

Was macht das Tool?
-------------------

Der MAXXKI Pseudonicer schaltet sich als Hook vor jede Anfrage in Claude Code
und ersetzt erkannte persönliche Daten automatisch durch Platzhalter – bevor
irgendetwas das lokale System verlässt.

Beispiel:

    "Mein Mandant Max Mustermann, IBAN: DE89 3704 0044 0532 0130 00, Tel: 0911-123456"

    wird zu:

    "Mein Mandant [FULL_NAME_1_a3f2], IBAN: [IBAN_1_b7c4], Tel: [PHONE_1_d2e1]"



Namen werden erkannt über Anreden (Herr, Frau, Dr., Prof., Mr., Mrs.)
sowie über Kontext-Labels im Text oder in JSON-Keys (Name, Kunde, User ...).

Obfuskierte PII werden ebenfalls erkannt:
  "m a x @ t e s t . d e"  ->  [EMAIL_1_...]
  "0 9 1 1 1 2 3 4 5 6"    ->  [PHONE_1_...]


Installation als Claude Code Hook
----

Schritt 1: Datei ablegen

    cp maxxki_pseudonicer.py ~/maxxki_pseudonicer.py

Schritt 2: settings.json einrichten

Im Paket liegt eine fertige settings.json bei. Diese einfach kopieren:

    macOS / Linux:
        cp settings.json ~/.claude/settings.json

    Windows:
        copy settings.json %APPDATA%\Claude\settings.json

    Falls bereits eine eigene settings.json existiert, den hooks-Block
    manuell einfügen (siehe Inhalt der mitgelieferten settings.json).

Schritt 3: Claude Code starten

    claude

Das war es. Der Hook ist jetzt aktiv und läuft unsichtbar im Hintergrund.
Es erscheint kein extra Fenster und kein Prompt – das Script arbeitet
automatisch bei jeder Anfrage. Claude Code verhält sich genauso wie gewohnt,
nur dass PII vorher herausgefiltert wird.


Hinweis zum Hintergrundverhalten
---

Das Script startet nicht sichtbar und "hängt" nicht. Es wird von Claude Code
bei Bedarf aufgerufen, verarbeitet den Text in Millisekunden und beendet sich
wieder. Nichts muss manuell gestartet oder offen gehalten werden.

Wenn man das Script direkt im Terminal aufruft (ohne Eingabe), wartet es auf
stdin – das sieht aus als würde es hängen, ist aber normal. Einfach mit
Strg+C beenden. Für den Hook-Betrieb ist das irrelevant.


Standalone-Nutzung (optional)
---

Einzelnen Text pseudonymisieren:

    echo "Frau Dr. Müller, IBAN: DE89 3704 0044 0532 0130 00" \
      | python3 maxxki_pseudonicer.py

Datei bereinigen (txt, md):

    cat dokument.txt | python3 maxxki_pseudonicer.py > dokument_clean.txt

PDF zuerst in Text umwandeln (benötigt poppler):

    pdftotext dokument.pdf - | python3 maxxki_pseudonicer.py > dokument_clean.txt

    poppler installieren in Termux:   pkg install poppler
    poppler installieren auf macOS:   brew install poppler
    poppler installieren auf Linux:   apt install poppler-utils

Interner Selbsttest:

    python3 maxxki_pseudonicer.py --test


Umgebungsvariablen
----

  SHOW_TYPE_IN_PLACEHOLDER   (Standard: true)
    true  ->  [EMAIL_1_3a7f]
    false ->  [REDACTED_3a7f]

  SECURE_ANONYMIZE   (Standard: true)
    true  ->  Mapping wird nach jeder Verarbeitung sofort gelöscht.
              Kein Rückschluss auf den Originalwert möglich.

  VALIDATE_CHECKSUMS   (Standard: true)
    true  ->  IBANs und Kreditkarten werden auf Gültigkeit geprüft.
              Ungültige Nummern werden nicht redacted.


Whitelist
--

Folgende Begriffe werden nie anonymisiert, auch wenn sie wie ein Name
oder Firmenname aussehen:

  Programmiersprachen:   Python, Java, Rust, Go, TypeScript, JavaScript ...
  Technologien:          Docker, Kubernetes, Git, Linux, macOS, AWS ...
  Städte / Länder:       Berlin, München, Hamburg, Deutschland, Germany ...
  Wochentage / Monate:   Montag, Januar, April ...

Die vollständige Liste (TECH_WHITELIST) ist im Quellcode direkt erweiterbar.


Sicherheitshinweise
---

  - Der Hook greift lokal – PII verlässt das System nie als Klartext.
  - Das Mapping (Platzhalter <-> Original) lebt nur im RAM, kein Logging.
  - Mit SECURE_ANONYMIZE=true (Standard) ist keine Rück-Pseudonymisierung
    möglich. Das ist so gewollt.
  - Das Tool ist kein Ersatz für rechtliche DSGVO-Maßnahmen, sondern eine
    technische Schutzschicht.



  maxxki_pseudonicer.py        Hauptmodul
  settings.json                Fertige Claude Code Konfiguration



Beispiel:
-----

nano dokument.txt

KUNDENANFRAGE - Vertraulich

Sehr geehrter Herr Dr. Thomas Schmidt,

vielen Dank für Ihre Anfrage vom 15.03.2024. 
Wir haben folgende Daten von Ihnen erfasst:

---
Persönliche Daten:
- Name: Thomas Schmidt
- Geburtsdatum: 15.03.1985
- E-Mail: thomas.schmidt@beispielfirma.de
- Telefon: +49 911 9876543
- Mobil: 0151-12345678
- Steuernummer: 21/815/08150
---

Bankverbindung:
IBAN: DE89 3704 0044 0532 0130 00
BIC: COBADEFFXXX
Kreditkarte: 4111 1111 1111 1111

---
Firmendaten:
Arbeitgeber: Beispielfirma GmbH
Adresse: Musterstraße 42a, 90403 Nürnberg
Kennzeichen: N AB 1234

---
API-Zugang:
api_key = "sk-abc123def456ghi789jkl012mno345"
token = "ghp_xyz789abc456def123ghi789jkl456mno"

---
Server-Infrastruktur:
IP-Adresse: 192.168.1.100
Gateway: 10.0.0.1

---
Notizen aus dem Gespräch mit Frau Anna Weber (weber@example.com):
"Herr Schmidt wohnt in der Berliner Straße 15 und ist seit 2020 Kunde.
Die Firma arbeitet mit Python, Docker und Kubernetes auf AWS."

---
Obfuskierte Daten (Spam-Schutz umgangen):
Email: m a x @ t e s t . d e
Telefon: 0 9 1 1 1 2 3 4 5 6 7 8

---
Viele Grüße
Ihr Support-Team

PS: Der Kunde nutzt Linux und entwickelt in TypeScript.
----------

Jetzt den Pseudonicer:

cat dokument.txt | python3 maxxki_pseudonicer.py > dokument_clean.txt



Version
-------

v6.0
