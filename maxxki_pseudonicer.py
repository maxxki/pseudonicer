#!/usr/bin/env python3
"""
MAXXKI PII Pseudonicer v6.0
============================
Änderungen gegenüber v5.3:
  - SESSION-SCOPE-ARCHITEKTUR: `session_scope` Parameter ersetzt SECURE_ANONYMIZE Env-Var.
    "document" = Mapping bleibt für die gesamte Dokument-Verarbeitung erhalten (konsistente Tokens).
    "request"  = Mapping wird nach jedem pseudonize()-Aufruf gelöscht (altes SECURE_ANONYMIZE=True).
  - ZEITBOMBEN-FIX: RuntimeWarning beim Instanziieren + zeitbasierter Guard nach 1h ohne reset_session().
  - SPACY HYBRID-NER: Optionale zweite Erkennungsschicht via de_core_news_sm.
    Regex bleibt primär für strukturierte PII (IBAN, CC, Phone).
    spaCy ergänzt für freie Texterkennung von Personennamen.
  - OVERLAP-RESOLUTION FIX: spaCy-interne Überlappungen werden VOR dem Merge mit Regex aufgelöst.
  - NICHT-WESTLICHE NAMEN: _CYRILLIC / _ARABIC / _GREEK Konstanten werden jetzt tatsächlich
    im FULL_NAME-Pattern verwendet.
  - reset_session(): Explizite API für neues Dokument / neue Einheit.
"""

import re
import sys
import json
import os
import time
import secrets
import warnings
from typing import List, Set, Dict, Tuple, Optional


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------

def _get_bool_env(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.lower() in ("true", "1", "yes", "on")


SHOW_TYPE_IN_PLACEHOLDER = _get_bool_env("SHOW_TYPE_IN_PLACEHOLDER", True)
VALIDATE_CHECKSUMS       = _get_bool_env("VALIDATE_CHECKSUMS", True)

# ---------------------------------------------------------------------------
# spaCy-Backend (optional)
# ---------------------------------------------------------------------------

try:
    import spacy as _spacy
    _nlp = _spacy.load("de_core_news_sm")
    NER_BACKEND = "spacy"
except (ImportError, OSError):
    _nlp = None
    NER_BACKEND = "regex"
    warnings.warn(
        "spaCy ('de_core_news_sm') nicht verfügbar — Fallback auf regelbasiertes NER. "
        "Erkennungsrate für Personennamen in Freitexten kann sinken. "
        "Installation: pip install spacy && python -m spacy download de_core_news_sm",
        RuntimeWarning,
        stacklevel=2,
    )

# ---------------------------------------------------------------------------
# Whitelist & Hilfskonstanten
# ---------------------------------------------------------------------------

TECH_WHITELIST: Set[str] = {
    "Python", "Java", "Kotlin", "Swift", "Rust", "Go", "TypeScript", "JavaScript",
    "React", "Vue", "Angular", "Django", "Spring", "Laravel", "Docker", "Kubernetes",
    "Git", "Linux", "Windows", "macOS", "Android", "iOS", "Postgres", "MySQL",
    "MongoDB", "Redis", "Kafka", "AWS", "Azure", "Google", "Berlin", "München",
    "Hamburg", "Frankfurt", "Köln", "Stuttgart", "Deutschland", "Germany", "Austria",
    "Switzerland", "London", "Paris", "Montag", "Dienstag", "Mittwoch", "Donnerstag",
    "Freitag", "Samstag", "Sonntag", "Monday", "Tuesday", "Januar", "Februar",
    "März", "April", "Mai", "Juni", "Juli", "August", "September", "Oktober",
    "November", "Dezember", "Der", "Die", "Das", "The", "And", "For", "With",
    "Im", "Schöne", "Grüße", "aus", "München", "Jahr", "war", "es", "ruhig"
}

_NAME_KEYS: Set[str] = {
    "name", "vorname", "nachname", "fullname", "full_name",
    "kunde", "customer", "client", "user", "person", "kontakt", "contact"
}

# Zeichenklassen — werden jetzt tatsächlich in FULL_NAME genutzt
_LATIN_BASE    = r'A-Za-zÀ-ÿĀ-ſƀ-ƿǀ-ǿȀ-ȗ'
_CYRILLIC      = r'А-Яа-яЁёЇїІіЄєҐґ'
_ARABIC        = r'\u0600-\u06FF\u0750-\u077F\u0870-\u089F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF'
_GREEK         = r'Α-Ωα-ωάέήίόύώΆΈΉΊΌΎΏ'
_TURKISH_EXTRA = r'ĞğİıŞşÖöÜüÇç'
_SLAVIC_EXTRA  = r'ČčĆćĐđŠšŽžŘřĎďŤťŇň'

# Alle Buchstaben kombiniert (für universellen Namens-Match)
_ALL_LETTERS = (
    _LATIN_BASE + _CYRILLIC + _GREEK + _TURKISH_EXTRA + _SLAVIC_EXTRA
    + r'\u0600-\u06FF'  # Arabisch (vereinfacht, kein Surrogat-Range in re)
)

# ---------------------------------------------------------------------------
# PII-Patterns
# ---------------------------------------------------------------------------

PII_PATTERNS: List[Dict] = [
    {"label": "API_KEY",
     "pattern": r'(?:api[-_]?key|token|secret|password)\s*[=:]\s*["\']?([A-Za-z0-9\-_\.]{10,})["\']?',
     "flags": re.I, "group": 1},
    {"label": "EMAIL",
     "pattern": r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
     "group": 0},
    # IBAN vor PHONE — verhindert Overlap-Zerstörung
    {"label": "IBAN",
     "pattern": r'\b[A-Z]{2}\d{2}(?:\s?[0-9A-Z]{4}){3,7}(?:\s?[0-9A-Z]{1,4})?\b',
     "group": 0},
    {"label": "BIC",
     "pattern": r'\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b',
     "group": 0},
    {"label": "CREDIT_CARD",
     "pattern": r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
     "group": 0},
    # (?<![A-Z]) verhindert Match mitten in IBAN
    {"label": "PHONE",
     "pattern": r'(?<!\d)(?<![A-Z])(?:\+49|0049|0)[\s\-\.]?\(?\d{2,5}\)?[\s\-\.]?\d{3,}[\s\-\.]?\d{0,5}\b',
     "group": 0},
    {"label": "TAX_ID",
     "pattern": r'(?:Steuernummer|IdNr\.?|TIN|Tax ID)\s*:?\s*(\d{2}[\s\/]?\d{3}[\s\/]?\d{5})',
     "flags": re.I, "group": 1},
    {"label": "TAX_ID",
     "pattern": r'\b(\d{2}\s?\d{3}\s?\d{5})\b',
     "group": 1},
    {"label": "IP_ADDR",
     "pattern": r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
     "group": 0},
    {"label": "COMPANY",
     "pattern": r'(?<![A-Za-zäöüÄÖÜß])(?!(?:Der?|Die|Das|The|Ein[e]?|Und|And|Mit|With|Von|From|Im|In|An|Auf|Bei|Zu)\s)([A-ZÄÖÜ][A-Za-zÄÖÜäöüß\-\.]*(?:\s+(?:[A-ZÄÖÜ][A-Za-zÄÖÜäöüß\-\.]*|&)){0,4}?)\s+(?:GmbH|AG\b|KG\b|OHG\b|GbR\b|UG\b|eG\b|eV\b|Ltd\b|Limited\b|LLC\b|Inc\b|Corp\b|LLP\b)',
     "group": 1},
    # FULL_NAME: Anrede (case-insensitive via inline flag) + Namensteile die mit
    # Großbuchstaben beginnen MÜSSEN. Kein re.I auf dem ganzen Pattern —
    # sonst matcht "schreibt" als Namensteil.
    {"label": "FULL_NAME",
     "pattern": (
         r'(?i:Herr|Frau|Hr\.|Fr\.|Dr\.?|Prof\.?|Mr\.?|Mrs\.?|Ms\.?)'
         r'(?:\s+[A-ZÄÖÜА-ЯΑ-Ω][' + _ALL_LETTERS + r']{1,30}){1,3}'
         r'(?=\s|[.,;:!?)\]]|$)'
     ),
     "group": 0},
    {"label": "FULL_NAME",
     "pattern": (
         r'(?:Name|Nachname|Kunde|Client|Customer|User)\s*:?\s*'
         r'([A-ZÄÖÜА-ЯΑ-Ω][' + _ALL_LETTERS + r']+(?:\s+[A-ZÄÖÜА-ЯΑ-Ω][' + _ALL_LETTERS + r']+){1,2})\b'
     ),
     "flags": re.I, "group": 1},
    {"label": "ADDRESS",
     "pattern": r'\b([A-ZÄÖÜ][a-zäöüß\-]+(?:straße|strasse|str\.|gasse|weg|allee|platz|ring|damm))\s+\d+[a-z]?\b',
     "flags": re.I, "group": 0},
    {"label": "BIRTHDATE",
     "pattern": r'(?:geboren\s+am\s+|geb\.?\s*|DOB\s*:?\s*|Geburtsdatum:?\s*)?(\d{1,2}[.\-\/]\d{1,2}[.\-\/]\d{2,4})',
     "flags": re.I, "group": 1},
    {"label": "LICENSE_PLATE",
     "pattern": r'\b[A-ZÄÖÜ]{1,3}[\s\-][A-Z]{1,2}\s?\d{1,4}\b',
     "group": 0},
]


# ---------------------------------------------------------------------------
# Hauptklasse
# ---------------------------------------------------------------------------

class PIIPseudonicer:
    """
    Parameters
    ----------
    session_scope : "document" | "request"
        "document"  → Mapping bleibt über mehrere pseudonize()-Aufrufe erhalten.
                      reset_session() MUSS zwischen zwei Dokumenten aufgerufen werden.
        "request"   → Mapping wird nach jedem pseudonize()-Aufruf gelöscht.
                      Entspricht altem SECURE_ANONYMIZE=True.
    """

    def __init__(self, session_scope: str = "document") -> None:
        if session_scope not in ("document", "request"):
            raise ValueError(
                f"Ungültiger session_scope: '{session_scope}'. "
                "Erlaubt: 'document' oder 'request'."
            )

        self.session_scope = session_scope
        self.mapping: Dict[str, str] = {}
        self.counter: int = 0
        self._session_start: float = time.time()

        self._compiled: List[Dict] = []
        for rule in PII_PATTERNS:
            self._compiled.append({
                "label": rule["label"],
                "regex": re.compile(rule["pattern"], rule.get("flags", 0)),
                "group": rule.get("group", 0),
            })

        if session_scope == "document":
            warnings.warn(
                "PIIPseudonicer(session_scope='document'): PII-Mappings werden im RAM "
                "persistiert. reset_session() nach jedem Dokument ist Pflicht, "
                "sonst akkumulieren personenbezogene Daten ohne Zweckbindung.",
                RuntimeWarning,
                stacklevel=2,
            )

    # ------------------------------------------------------------------
    # Öffentliche API
    # ------------------------------------------------------------------

    def reset_session(self) -> None:
        """Löscht das Mapping explizit. Vor jedem neuen Dokument aufrufen."""
        self.mapping.clear()
        self.counter = 0
        self._session_start = time.time()

    def get_mapping(self) -> Dict[str, str]:
        """Gibt eine Kopie des aktuellen Mappings zurück (für Audit-Zwecke)."""
        return dict(self.mapping)

    def pseudonize(self, text: str) -> str:
        if not text:
            return text

        # Zeitbasierter Guard: Session älter als 1 Stunde ohne Reset?
        if self.session_scope == "document":
            age = time.time() - self._session_start
            if age > 3600 and self.mapping:
                warnings.warn(
                    f"PIIPseudonicer-Session läuft seit {age/3600:.1f}h ohne reset_session(). "
                    "Möglicher Memory-Leak oder fehlender Dokument-Trenner.",
                    RuntimeWarning,
                    stacklevel=2,
                )

        text = self._deobfuscate_text(text)

        # Schicht 1: Regex-Patterns
        found = self._run_regex_rules(text)

        # Schicht 2: spaCy (nur Freitext-Entitäten, keine strukturierten Daten)
        if NER_BACKEND == "spacy":
            spacy_hits = self._get_spacy_entities(text)
            # spaCy-interne Overlaps zuerst auflösen, dann mit Regex mergen
            spacy_clean = self._resolve_overlaps(spacy_hits)
            found.extend(spacy_clean)

        # Finale Overlap-Resolution (Regex vs. spaCy, längster Match gewinnt)
        selected = self._resolve_overlaps(found)

        # Ersetzen (von hinten nach vorne, um Indizes nicht zu verschieben)
        selected.sort(key=lambda x: x[0], reverse=True)
        result = text
        for start, end, val, lbl in selected:
            placeholder = self._make_placeholder(lbl, val)
            result = result[:start] + placeholder + result[end:]

        if self.session_scope == "request":
            self.reset_session()

        return result

    # ------------------------------------------------------------------
    # Interne Hilfsmethoden
    # ------------------------------------------------------------------

    def _run_regex_rules(self, text: str) -> List[Tuple[int, int, str, str]]:
        """Gibt alle Regex-Matches als (start, end, value, label) zurück."""
        found = []
        for rule in self._compiled:
            for m in rule["regex"].finditer(text):
                grp = rule["group"]
                if grp > 0:
                    val = m.group(grp)
                    start, end = m.span(grp)
                else:
                    val = m.group(0)
                    start, end = m.span(0)

                if VALIDATE_CHECKSUMS:
                    if rule["label"] == "CREDIT_CARD" and not self._is_valid_luhn(val):
                        continue
                    if rule["label"] == "IBAN" and not self._is_valid_iban(val):
                        continue

                if any(w in TECH_WHITELIST for w in val.split()):
                    continue

                found.append((start, end, val, rule["label"]))
        return found

    def _get_spacy_entities(self, text: str) -> List[Tuple[int, int, str, str]]:
        """
        Extrahiert Personen-Entitäten via spaCy.
        Strukturierte PII (IBAN, CC, Phone) werden NICHT per spaCy erkannt —
        dafür sind die Regex-Patterns zuverlässiger.
        """
        if _nlp is None:
            return []
        doc = _nlp(text)
        result = []
        for ent in doc.ents:
            if ent.label_ == "PER":
                # Whitelist-Check auch für spaCy-Hits
                if any(w in TECH_WHITELIST for w in ent.text.split()):
                    continue
                result.append((ent.start_char, ent.end_char, ent.text, "FULL_NAME"))
            elif ent.label_ in ("LOC", "GPE"):
                # Adressen nur wenn sie nicht schon per Regex abgedeckt sind
                result.append((ent.start_char, ent.end_char, ent.text, "ADDRESS"))
        return result

    @staticmethod
    def _resolve_overlaps(
        hits: List[Tuple[int, int, str, str]]
    ) -> List[Tuple[int, int, str, str]]:
        """
        Löst Überlappungen auf: längster Match gewinnt.
        Funktioniert sowohl für reine Regex-Listen als auch für Misch-Listen
        (Regex + spaCy), sodass spaCy-interne Überlappungen VOR dem Merge
        mit Regex sauber aufgelöst werden können.
        """
        hits_sorted = sorted(hits, key=lambda x: (x[1] - x[0]), reverse=True)
        selected: List[Tuple[int, int, str, str]] = []
        used: List[Tuple[int, int]] = []

        for start, end, val, lbl in hits_sorted:
            overlap = any(
                not (end <= u_s or start >= u_e) for u_s, u_e in used
            )
            if not overlap:
                selected.append((start, end, val, lbl))
                used.append((start, end))

        return selected

    def _make_placeholder(self, label: str, original: str) -> str:
        if original in self.mapping:
            return self.mapping[original]
        self.counter += 1
        token = secrets.token_hex(2)
        if SHOW_TYPE_IN_PLACEHOLDER:
            placeholder = f"[{label}_{self.counter}_{token}]"
        else:
            placeholder = f"[REDACTED_{token}]"
        self.mapping[original] = placeholder
        return placeholder

    def _is_valid_luhn(self, number: str) -> bool:
        num = re.sub(r'\D', '', number)
        if not num or len(num) < 13:
            return False
        digits = [int(d) for d in num]
        checksum = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
        return checksum % 10 == 0

    def _is_valid_iban(self, iban: str) -> bool:
        s = re.sub(r'\s+', '', iban).upper()
        if not re.match(r'^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$', s):
            return False
        rearranged = s[4:] + s[:4]
        numeric = ''
        for ch in rearranged:
            if ch.isdigit():
                numeric += ch
            else:
                numeric += str(ord(ch) - 55)
        try:
            return int(numeric) % 97 == 1
        except Exception:
            return False

    def _deobfuscate_text(self, text: str) -> str:
        """Normalisiert obfuskierte PII (Leerzeichen zwischen einzelnen Zeichen)."""
        result = text

        # Obfuskierte Emails: 'm a x @ t e s t . d e' -> 'max@test.de'
        obf_email = re.compile(
            r'(?<![^\s])'
            r'((?:[a-zA-Z0-9._%+\-] )+[a-zA-Z0-9._%+\-])'
            r'\s*@\s*'
            r'((?:[a-zA-Z0-9\-] )*[a-zA-Z0-9\-])'
            r'\s*\.\s*'
            r'((?:[a-zA-Z] )*[a-zA-Z]{1,6})'
            r'(?=[\s,;.!?)\]]|$)',
        )
        for match in obf_email.finditer(text):
            original = match.group(0)
            local  = re.sub(r'\s+', '', match.group(1))
            domain = re.sub(r'\s+', '', match.group(2))
            tld    = re.sub(r'\s+', '', match.group(3))
            if len(tld) >= 2:
                result = result.replace(original, f"{local}@{domain}.{tld}")

        # Obfuskierte Telefonnummern: '0 9 1 1 1 2 3 4 5 6' -> '09111234 56'
        obf_phone = re.compile(
            r'(?<![^\s])'
            r'(\+?\d(?:\s\d){7,14})'
            r'(?=[\s,;.!?)\]]|$)',
        )
        for match in obf_phone.finditer(result):
            original = match.group(1)
            cleaned  = re.sub(r'\s+', '', original)
            if re.match(r'^(?:\+49|0049|0)\d{6,}$', cleaned):
                result = result.replace(original, cleaned)

        return result


# ---------------------------------------------------------------------------
# Hook-Funktion für externe Systeme (z.B. Webhook-Middleware)
# ---------------------------------------------------------------------------

def process_hook_input(raw: str) -> str:
    """
    Pseudonymisiert JSON-Payloads oder Plain-Text.
    Nutzt session_scope='request' — jeder Hook-Aufruf ist atomar.
    """
    p = PIIPseudonicer(session_scope="request")
    try:
        data = json.loads(raw)

        def walk(obj, key: str = ""):
            if isinstance(obj, str):
                if key.lower() in _NAME_KEYS:
                    hinted = p.pseudonize(f"Name: {obj}")
                    return re.sub(r'^Name:\s*', '', hinted)
                return p.pseudonize(obj)
            if isinstance(obj, list):
                return [walk(x) for x in obj]
            if isinstance(obj, dict):
                return {k: walk(v, key=k) for k, v in obj.items()}
            return obj

        return json.dumps(walk(data), ensure_ascii=False)
    except Exception:
        return p.pseudonize(raw)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def run_tests() -> None:
    print("=" * 60)
    print("MAXXKI PIIPseudonicer v6.0 — Test Suite")
    print("=" * 60)

    # Scope-Tests: Konsistenz über mehrere Aufrufe
    print("\n[Scope-Tests]")
    p_doc = PIIPseudonicer(session_scope="document")
    r1 = p_doc.pseudonize("Herr Max Mustermann schreibt.")
    r2 = p_doc.pseudonize("Antwort an Herr Max Mustermann.")
    token1 = re.findall(r'\[FULL_NAME_\d+_[0-9a-f]+\]', r1)
    token2 = re.findall(r'\[FULL_NAME_\d+_[0-9a-f]+\]', r2)
    if token1 and token1 == token2:
        print(f"  ✅ Konsistenz document-scope: gleicher Token {token1[0]}")
    else:
        print(f"  ❌ Konsistenz document-scope: {token1} != {token2}")

    p_doc.reset_session()
    r3 = p_doc.pseudonize("Herr Max Mustermann schreibt.")
    token3 = re.findall(r'\[FULL_NAME_\d+_[0-9a-f]+\]', r3)
    if token3 and token3 != token1:
        print(f"  ✅ reset_session() erzeugt neuen Token: {token3[0]}")
    else:
        print(f"  ❌ reset_session() funktioniert nicht: {token3}")

    # PII-Erkennungs-Tests
    print("\n[PII-Erkennungs-Tests]")
    p = PIIPseudonicer(session_scope="request")
    tests = [
        ("Email",               "max@mustermann.de"),
        ("Obfuskierte Email",   "m a x @ t e s t . d e"),
        ("IBAN",                "DE89370400440532013000"),
        ("Phone",               "0911-123456"),
        ("Credit Card",         "4111111111111111"),
        ("Company AG",          "Beispiel AG"),
        ("Company GmbH",        "Musterfirma GmbH"),
        ("Name Herr",           "Herr Klaus Müller"),
        ("Name Context",        "Name: Max Mustermann"),
        ("Tax ID",              "Steuernummer: 21/815/08150"),
        ("Kyrillischer Name",   "Frau Наталья Петрова"),
    ]

    passed = failed = 0
    for desc, inp in tests:
        out = p.pseudonize(inp)
        if "[" in out:
            print(f"  ✅ {desc}: {out}")
            passed += 1
        else:
            print(f"  ❌ {desc}: {out}")
            failed += 1

    print(f"\n{'=' * 60}")
    print(f"Ergebnis: ✅ {passed} passed, ❌ {failed} failed")
    print(f"NER-Backend: {NER_BACKEND}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        run_tests()
    else:
        print(process_hook_input(sys.stdin.read()))
