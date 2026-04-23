#!/usr/bin/env python3
"""
MAXXKI PII Pseudonicer v5.3 - All Tests Passing
Fixes vs v5.2:
  - IBAN-Regex: trailing-Gruppe {1,4} statt fest {4} (DE89...0130 00 vollständig matchen)
  - IBAN vor PHONE in PII_PATTERNS (Overlap-Resolver bevorzugt längeren Match)
  - PHONE: (?<![A-Z]) verhindert Match innerhalb von IBANs
  - COMPANY: Artikel-Stopper + sauberer Lookbehind -> "Die Beispiel AG" nimmt nur "Beispiel"
  - process_hook_input: Name-Keys ("name","user",...) geben FULL_NAME-Kontext-Hint
  - _deobfuscate_text: Neue Regex für Emails mit getrennter TLD ("d e" -> "de")
  - _deobfuscate_text: Neuer Deobfuskierer für Telefonnummern ("0 9 1 1 ..." -> "0911...")
"""

import re
import sys
import json
import os
import secrets
from typing import List, Set, Dict

def _get_bool_env(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None: return default
    return val.lower() in ("true", "1", "yes", "on")

SHOW_TYPE_IN_PLACEHOLDER = _get_bool_env("SHOW_TYPE_IN_PLACEHOLDER", True)
SECURE_ANONYMIZE         = _get_bool_env("SECURE_ANONYMIZE", True)
VALIDATE_CHECKSUMS       = _get_bool_env("VALIDATE_CHECKSUMS", True)

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

# JSON-Keys die auf einen Personennamen hinweisen
_NAME_KEYS: Set[str] = {
    "name", "vorname", "nachname", "fullname", "full_name",
    "kunde", "customer", "client", "user", "person", "kontakt", "contact"
}

_LATIN_BASE    = r'A-Za-zÀ-ÿĀ-ſƀ-ƿǀ-ǿȀ-ȗ'
_CYRILLIC      = r'А-Яа-яЁёЇїІіЄєҐґ'
_ARABIC        = r'\u0600-\u06FF\u0750-\u077F\u0870-\u089F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF'
_GREEK         = r'Α-Ωα-ωάέήίόύώΆΈΉΊΌΎΏ'
_TURKISH_EXTRA = r'ĞğİıŞşÖöÜüÇç'
_SLAVIC_EXTRA  = r'ČčĆćĐđŠšŽžŘřĎďŤťŇň'

PII_PATTERNS: List[Dict] = [
    {"label": "API_KEY",
     "pattern": r'(?:api[-_]?key|token|secret|password)\s*[=:]\s*["\']?([A-Za-z0-9\-_\.]{10,})["\']?',
     "flags": re.I, "group": 1},
    {"label": "EMAIL",
     "pattern": r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
     "group": 0},
    # IBAN vor PHONE – verhindert Zerstörung der IBAN durch PHONE-Pattern.
    # Trailing-Gruppe {1,4} erlaubt kurze Restblöcke ("... 0130 00").
    {"label": "IBAN",
     "pattern": r'\b[A-Z]{2}\d{2}(?:\s?[0-9A-Z]{4}){3,7}(?:\s?[0-9A-Z]{1,4})?\b',
     "group": 0},
    {"label": "BIC",
     "pattern": r'\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b',
     "group": 0},
    {"label": "CREDIT_CARD",
     "pattern": r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
     "group": 0},
    # (?<![A-Z]) verhindert Match mitten in einer IBAN
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
    # Lookbehind auf Nicht-Buchstabe + Artikel-Negation -> "Die Beispiel AG" matcht nur "Beispiel"
    {"label": "COMPANY",
     "pattern": r'(?<![A-Za-zäöüÄÖÜß])(?!(?:Der?|Die|Das|The|Ein[e]?|Und|And|Mit|With|Von|From|Im|In|An|Auf|Bei|Zu)\s)([A-ZÄÖÜ][A-Za-zÄÖÜäöüß\-\.]*(?:\s+(?:[A-ZÄÖÜ][A-Za-zÄÖÜäöüß\-\.]*|&)){0,4}?)\s+(?:GmbH|AG\b|KG\b|OHG\b|GbR\b|UG\b|eG\b|eV\b|Ltd\b|Limited\b|LLC\b|Inc\b|Corp\b|LLP\b)',
     "group": 1},
    {"label": "FULL_NAME",
     "pattern": r'\b(?:Herr|Frau|Hr\.|Fr\.|Dr\.?|Prof\.?|Mr\.?|Mrs\.?|Ms\.?)\s+([A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß]+){0,2})\b',
     "flags": re.I, "group": 1},
    {"label": "FULL_NAME",
     "pattern": r'(?:Name|Nachname|Kunde|Client|Customer|User)\s*:?\s*([A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß]+){1,2})\b',
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


class PIIPseudonicer:
    def __init__(self) -> None:
        self.mapping: Dict[str, str] = {}
        self.counter: int = 0
        self._compiled = []
        for rule in PII_PATTERNS:
            self._compiled.append({
                "label": rule["label"],
                "regex": re.compile(rule["pattern"], rule.get("flags", 0)),
                "group": rule.get("group", 0)
            })

    def get_mapping(self) -> Dict[str, str]:
        return self.mapping

    def _is_valid_luhn(self, number: str) -> bool:
        num = re.sub(r'\D', '', number)
        if not num or len(num) < 13: return False
        digits = [int(d) for d in num]
        checksum = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9: d -= 9
            checksum += d
        return checksum % 10 == 0

    def _is_valid_iban(self, iban: str) -> bool:
        s = re.sub(r'\s+', '', iban).upper()
        if not re.match(r'^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$', s): return False
        numeric = ''
        rearranged = s[4:] + s[:4]
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
        """Normalisiert obfuskierte PII (Leerzeichen zwischen den Zeichen).

        Email: 'm a x @ t e s t . d e'  -> 'max@test.de'
        Phone: '0 9 1 1 1 2 3 4 5 6'    -> '09111234 56' (nur dt. Nummern)
        """
        result = text

        # Obfuskierte Emails:
        # lokaler Teil und Domain sind einzelne Zeichen mit Leerzeichen getrennt,
        # TLD wird separat gematcht damit "d e" korrekt -> "de" wird.
        obf_email = re.compile(
            r'(?<![^\s])'                                    # kein Nicht-Leerzeichen direkt davor
            r'((?:[a-zA-Z0-9._%+\-] )+[a-zA-Z0-9._%+\-])'  # lokaler Teil: "m a x"
            r'\s*@\s*'                                        # @
            r'((?:[a-zA-Z0-9\-] )*[a-zA-Z0-9\-])'           # domain: "t e s t"
            r'\s*\.\s*'                                       # Punkt
            r'((?:[a-zA-Z] )*[a-zA-Z]{1,6})'                # TLD: "d e" oder "com"
            r'(?=[\s,;.!?)\]]|$)',                                     # kein Nicht-Leerzeichen direkt danach
        )
        for match in obf_email.finditer(text):
            original = match.group(0)
            local  = re.sub(r'\s+', '', match.group(1))
            domain = re.sub(r'\s+', '', match.group(2))
            tld    = re.sub(r'\s+', '', match.group(3))
            if len(tld) >= 2:
                result = result.replace(original, f"{local}@{domain}.{tld}")

        # Obfuskierte Telefonnummern: "0 9 1 1 1 2 3 4 5 6" -> "09111234 56"
        obf_phone = re.compile(
            r'(?<![^\s])'            # kein Nicht-Leerzeichen direkt davor
            r'(\+?\d(?:\s\d){7,14})' # mind. 8 Ziffern je durch ein Leerzeichen getrennt
            r'(?=[\s,;.!?)\]]|$)',            # kein Nicht-Leerzeichen direkt danach
        )
        for match in obf_phone.finditer(result):
            original = match.group(1)
            cleaned  = re.sub(r'\s+', '', original)
            if re.match(r'^(?:\+49|0049|0)\d{6,}$', cleaned):
                result = result.replace(original, cleaned)

        return result

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

    def pseudonize(self, text: str) -> str:
        if not text: return text

        text = self._deobfuscate_text(text)

        found = []
        for rule in self._compiled:
            for m in rule["regex"].finditer(text):
                grp = rule["group"]
                if grp > 0:
                    val   = m.group(grp)
                    start, end = m.span(grp)
                else:
                    val   = m.group(0)
                    start, end = m.span(0)

                if VALIDATE_CHECKSUMS:
                    if rule["label"] == "CREDIT_CARD" and not self._is_valid_luhn(val):
                        continue
                    if rule["label"] == "IBAN" and not self._is_valid_iban(val):
                        continue

                if any(w in TECH_WHITELIST for w in val.split()):
                    continue

                found.append((start, end, val, rule["label"]))

        # Längster Match gewinnt bei Überlappung (IBAN schlägt PHONE)
        found.sort(key=lambda x: (x[1] - x[0]), reverse=True)
        selected: list = []
        used_positions: list = []

        for start, end, val, lbl in found:
            overlap = any(not (end <= u_s or start >= u_e) for u_s, u_e in used_positions)
            if not overlap:
                selected.append((start, end, val, lbl))
                used_positions.append((start, end))

        selected.sort(key=lambda x: x[0], reverse=True)
        result = text
        for start, end, val, lbl in selected:
            placeholder = self._make_placeholder(lbl, val)
            result = result[:start] + placeholder + result[end:]

        if SECURE_ANONYMIZE:
            self.mapping.clear()
            self.counter = 0

        return result


def process_hook_input(raw: str) -> str:
    p = PIIPseudonicer()
    try:
        data = json.loads(raw)

        def walk(obj, key: str = ""):
            if isinstance(obj, str):
                # Wenn der JSON-Key auf einen Personennamen hindeutet,
                # Kontext-Hint einfügen damit FULL_NAME-Pattern greift.
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


def run_tests() -> None:
    p = PIIPseudonicer()
    tests = [
        ("Email",             "max@mustermann.de",          "["),
        ("Obfuscated Email",  "m a x @ t e s t . d e",     "["),
        ("IBAN",              "DE89370400440532013000",      "["),
        ("Phone",             "0911-123456",                 "["),
        ("Credit Card",       "4111111111111111",            "["),
        ("Company AG",        "Beispiel AG",                 "["),
        ("Company GmbH",      "Musterfirma GmbH",            "["),
        ("Name Herr",         "Herr Klaus Müller",           "["),
        ("Name Context",      "Name: Max Mustermann",        "["),
        ("Tax ID",            "Steuernummer: 21/815/08150",  "["),
    ]

    passed = failed = 0
    for desc, inp, _ in tests:
        out = p.pseudonize(inp)
        if "[" in out:
            print(f"✅ {desc}: {out}")
            passed += 1
        else:
            print(f"❌ {desc}: {out}")
            failed += 1

    print(f"\n✅ {passed} passed, ❌ {failed} failed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        run_tests()
    else:
        print(process_hook_input(sys.stdin.read()))
