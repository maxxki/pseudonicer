# MAXXKI HR-Automator & PII-Pseudonicer 🚀

Ein professionelles Framework zur datenschutzkonformen Automatisierung von HR-Dokumenten und zur Neutralisierung personenbezogener Daten (PII) gemäß DSGVO und EU AI Act.

## 🌟 Kern-Features

*   **Privacy-by-Design:** Pseudonymisierung aller personenbezogenen Daten in Logs und Konsolenausgaben in Echtzeit.
*   **Rechtssicherheit:** Integrierter "Compliance-Gate", der eine gültige DSGVO-Rechtsgrundlage (Art. 6) vor der Verarbeitung erzwingt.
*   **Hybrid-NER Engine:** Kombination aus Deep Learning (spaCy) für natürliche Sprache und deterministischen Algorithmen (Regex + Prüfsummen) für strukturierte Daten (IBAN, Kreditkarten, Steuernummern).
*   **Audit-Ready:** Automatisiertes, PII-freies Event-Logging zur Erfüllung der Rechenschaftspflicht (Art. 5 Abs. 2 DSGVO).
*   **Security Hardened:** Schutz gegen Path-Traversal und Injektions-Angriffe durch strikte Input-Sanitierung.

---

## 🛠 Installation

Das System ist für den Betrieb in einer Python 3.10+ Umgebung optimiert.

```bash
# 1. Abhängigkeiten installieren
pip install -r requirements.txt

# 2. Deutschsprachiges KI-Modell laden
pip install https://github.com/explosion/spacy-models/releases/download/de_core_news_sm-3.8.0/de_core_news_sm-3.8.0-py3-none-any.whl

```

---

## 🚀 Use Cases

### 1. Automatisierte HR-Dokumentenerstellung (Self-Service)
Erstellung von Arbeitsverträgen, Zeugnissen oder Nachträgen basierend auf JSON-Inputs aus einem ERP- oder HR-Portal.
*   **Vorteil:** Schnelle Generierung ohne manuelles Copy-Paste-Risiko.
*   **Compliance:** Jedes Dokument wird mit der korrekten Rechtsgrundlage (z. B. "Vertragserfüllung") verknüpft und auditiert.

### 2. Neutralisierung von Daten für Analytics & Reporting
Export von HR-Daten für statistische Auswertungen oder externe Berater, ohne Klardaten preiszugeben.
*   **Vorteil:** Der `PIIPseudonicer` ersetzt Namen und Identifikatoren durch konsistente Tokens. So bleiben Trends (z. B. "Fluktuation in Abteilung X") analysierbar, während die Anonymität der Mitarbeiter gewahrt bleibt.

### 3. Sicheres Debugging & Support-Logs
Entwickler oder IT-Support können System-Logs einsehen, ohne Zugriff auf tatsächliche Mitarbeiterdaten zu erhalten.
*   **Vorteil:** Der `PII-GUARD` filtert sensible Informationen automatisch aus der Konsolenausgabe.

---

## 💻 Anwendung

### Demo-Modus starten
```bash
python3 hr_gen.py --demo
```

### Eigenen Datensatz verarbeiten
Erstellen Sie eine `input.json`:
```json
{
    "vorname": "Erika",
    "nachname": "Mustermann",
    "position": "Software Engineer",
    "rechtsgrundlage": "art6_1b"
}
```
Führen Sie den Automator aus:
```bash
python3 hr_gen.py --type vertrag --input input.json
```

---

## 📁 Projektstruktur
*   `hr_gen.py`: Hauptlogik für Dokumentengenerierung und Audit-Enforcement.
*   `maxxki_pseudonicer.py`: Die Core-Engine zur PII-Erkennung und Pseudonymisierung.
*   `templates/`: Word-Vorlagen (`.docx`) mit Platzhaltern wie `{{NACHNAME}}`.
*   `output/`: Zielverzeichnis für generierte Dokumente (Sollte verschlüsselt sein!).
*   `audit/`: Revisionssichere JSON-Lines Logs.

---

## ⚖️ Rechtlicher Hinweis
Dieses System unterstützt bei der Einhaltung der DSGVO und des EU AI Acts auf technischer Ebene. Die organisatorische Compliance (z. B. Erstellung eines Verzeichnisses von Verarbeitungstätigkeiten) obliegt dem Betreiber.
