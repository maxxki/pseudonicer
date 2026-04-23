#!/usr/bin/env python3
"""
MAXXKI PII Pseudonicer v5.3 — Test Suite
"""

import json
import sys
import unittest
import re
import os

sys.path.insert(0, ".")
try:
    from maxxki_pseudonicer import PIIPseudonicer, process_hook_input
except ImportError:
    print("FEHLER: maxxki_pseudonicer.py nicht gefunden.")
    sys.exit(1)


def pseudonize(text: str) -> str:
    return PIIPseudonicer().pseudonize(text)


class TestEmail(unittest.TestCase):
    def test_simple_email(self):
        r = pseudonize("Schreib an max.mustermann@example.com bitte.")
        self.assertNotIn("max.mustermann@example.com", r)
        self.assertIn("[EMAIL_", r)

    def test_email_with_plus(self):
        r = pseudonize("Filter: user+tag@domain.org")
        self.assertNotIn("user+tag@domain.org", r)
        self.assertIn("[EMAIL_", r)

    def test_no_false_positive_email_like(self):
        r = pseudonize("Das ist kein Email: nurtext.ohne.at")
        self.assertEqual(r, "Das ist kein Email: nurtext.ohne.at")

    def test_obfuscated_email(self):
        """v5.1: Obfuskierte Email wird erkannt"""
        r = pseudonize("Kontakt: m a x @ t e s t . d e")
        self.assertIn("[EMAIL_", r)


class TestPhone(unittest.TestCase):
    def test_de_prefix(self):
        r = pseudonize("Ruf mich an: 0911-123456")
        self.assertNotIn("0911-123456", r)
        self.assertIn("[PHONE_", r)

    def test_de_plus49(self):
        r = pseudonize("Tel: +49 89 12345678")
        self.assertNotIn("+49 89 12345678", r)
        self.assertIn("[PHONE_", r)

    def test_no_false_positive_year(self):
        r = pseudonize("Im Jahr 2024 war es ruhig.")
        self.assertEqual(r, "Im Jahr 2024 war es ruhig.")


class TestIBAN(unittest.TestCase):
    def test_german_iban(self):
        r = pseudonize("IBAN: DE89 3704 0044 0532 0130 00")
        self.assertNotIn("DE89 3704 0044 0532 0130 00", r)
        self.assertIn("[IBAN_", r)

    def test_invalid_iban_not_redacted(self):
        """v5.1: Ungültige IBAN wird NICHT redacted (Validierung)"""
        r = pseudonize("IBAN: DE99123456789012345678")
        self.assertIn("DE99123456789012345678", r)
        self.assertNotIn("[IBAN_", r)


class TestCreditCard(unittest.TestCase):
    def test_visa(self):
        r = pseudonize("Visa: 4111111111111111")
        self.assertNotIn("4111111111111111", r)
        self.assertIn("[CREDIT_CARD_", r)

    def test_invalid_credit_card_not_redacted(self):
        """v5.1: Ungültige Kreditkarte (Luhn fail) wird NICHT redacted"""
        r = pseudonize("Karte: 1234567890123456")
        self.assertIn("1234567890123456", r)
        self.assertNotIn("[CREDIT_CARD_", r)


class TestIPAddress(unittest.TestCase):
    def test_ipv4(self):
        r = pseudonize("Server läuft auf 192.168.1.100")
        self.assertNotIn("192.168.1.100", r)
        self.assertIn("[IP_ADDR_", r)


class TestAPIKey(unittest.TestCase):
    def test_api_key_label(self):
        r = pseudonize('api_key = "sk-abc123def456ghi789jkl012mno"')
        self.assertNotIn("sk-abc123def456ghi789jkl012mno", r)
        self.assertIn("[API_KEY_", r)

    def test_short_value_not_redacted(self):
        r = pseudonize('api_key = "kurz"')
        self.assertIn("kurz", r)


class TestAddress(unittest.TestCase):
    def test_german_street(self):
        r = pseudonize("Wohnhaft in der Musterstraße 42a")
        self.assertNotIn("Musterstraße 42a", r)
        self.assertIn("[ADDRESS_", r)


class TestBirthdate(unittest.TestCase):
    def test_dot_format(self):
        r = pseudonize("Geboren am 15.03.1985")
        self.assertNotIn("15.03.1985", r)
        self.assertIn("[BIRTHDATE_", r)


class TestTaxID(unittest.TestCase):
    def test_steuernummer(self):
        r = pseudonize("Steuernummer: 21/815/08150")
        self.assertNotIn("21/815/08150", r)
        self.assertIn("[TAX_ID_", r)


class TestNames(unittest.TestCase):
    def test_herr_name(self):
        r = pseudonize("Sehr geehrter Herr Klaus Müller,")
        self.assertNotIn("Klaus Müller", r)
        self.assertIn("[FULL_NAME_", r)

    def test_frau_name(self):
        r = pseudonize("Liebe Frau Anna Schmidt,")
        self.assertNotIn("Anna Schmidt", r)
        self.assertIn("[FULL_NAME_", r)

    def test_dr_name(self):
        r = pseudonize("Dr. Maria Weber hat angerufen.")
        self.assertNotIn("Maria Weber", r)
        self.assertIn("[FULL_NAME_", r)

    def test_context_label_name(self):
        r = pseudonize("Name: Max Mustermann")
        self.assertNotIn("Max Mustermann", r)
        self.assertIn("[FULL_NAME_", r)


class TestCompany(unittest.TestCase):
    def test_gmbh(self):
        r = pseudonize("Auftraggeber: Musterfirma GmbH")
        self.assertNotIn("Musterfirma GmbH", r)
        self.assertIn("[COMPANY_", r)

    def test_ag(self):
        r = pseudonize("Die Beispiel AG hat bestätigt.")
        self.assertNotIn("Beispiel AG", r)
        self.assertIn("[COMPANY_", r)


class TestWhitelist(unittest.TestCase):
    def test_python_not_redacted(self):
        r = pseudonize("Ich schreibe den Code in Python.")
        self.assertIn("Python", r)
        self.assertNotIn("[", r)

    def test_berlin_not_redacted(self):
        r = pseudonize("Das Büro liegt in Berlin.")
        self.assertIn("Berlin", r)

    def test_docker_not_redacted(self):
        r = pseudonize("Deployment via Docker.")
        self.assertIn("Docker", r)


class TestJSONProcessing(unittest.TestCase):
    def test_valid_json_string_field(self):
        payload = json.dumps({"message": "Kontakt: max@example.com"})
        result = process_hook_input(payload)
        data = json.loads(result)
        self.assertNotIn("max@example.com", data["message"])
        self.assertIn("[EMAIL_", data["message"])

    def test_nested_json(self):
        payload = json.dumps({
            "user": {"name": "Max Mustermann", "email": "max@test.de"}
        })
        result = process_hook_input(payload)
        data = json.loads(result)
        self.assertNotIn("max@test.de", data["user"]["email"])
        self.assertIn("[FULL_NAME_", data["user"]["name"])

    def test_invalid_json_plaintext_fallback(self):
        plain = "kein JSON, aber max@example.com drin"
        result = process_hook_input(plain)
        self.assertNotIn("max@example.com", result)

    def test_non_string_values_untouched(self):
        payload = json.dumps({"count": 42, "active": True})
        result = process_hook_input(payload)
        data = json.loads(result)
        self.assertEqual(data["count"], 42)
        self.assertEqual(data["active"], True)


class TestPlaceholderConsistency(unittest.TestCase):
    def test_same_value_same_placeholder(self):
        p = PIIPseudonicer()
        r = p.pseudonize("test@example.com und nochmal test@example.com")
        matches = re.findall(r'\[EMAIL_(\d+)_[a-f0-9]{4}\]', r)
        if len(matches) >= 2:
            self.assertEqual(matches[0], matches[1])
        else:
            self.fail(f"Nicht genug Platzhalter gefunden: {r}")

    def test_mapping_cleared_on_secure(self):
        """v5.1: Bei SECURE_ANONYMIZE wird Mapping gelöscht"""
        os.environ["SECURE_ANONYMIZE"] = "true"
        p = PIIPseudonicer()
        p.pseudonize("test@example.com")
        self.assertEqual(len(p.get_mapping()), 0)
        os.environ["SECURE_ANONYMIZE"] = "true"  # reset


class TestEdgeCases(unittest.TestCase):
    def test_empty_string(self):
        r = pseudonize("")
        self.assertEqual(r, "")

    def test_no_pii(self):
        text = "Das ist ein normaler Satz."
        r = pseudonize(text)
        self.assertEqual(r, text)

    def test_unicode_preserved(self):
        text = "Schöne Grüße aus München"
        r = pseudonize(text)
        self.assertEqual(r, text)

    def test_newlines_preserved(self):
        text = "Zeile 1\nZeile 2\nZeile 3"
        r = pseudonize(text)
        self.assertEqual(r.count("\n"), 2)


class TestLicensePlate(unittest.TestCase):
    def test_de_plate(self):
        r = pseudonize("Fahrzeug: M AB 1234")
        self.assertNotIn("M AB 1234", r)
        self.assertIn("[LICENSE_PLATE_", r)


class TestRealisticScenario(unittest.TestCase):
    def test_customer_inquiry(self):
        text = (
            "Kundenanfrage von Herr Thomas Becker (thomas.becker@firma.de), "
            "Tel: +49 911 998877, IBAN: DE12 3456 7890 1234 5678 90."
        )
        r = pseudonize(text)
        self.assertNotIn("Thomas Becker", r)
        self.assertNotIn("thomas.becker@firma.de", r)
        self.assertNotIn("+49 911 998877", r)
        self.assertIn("[FULL_NAME_", r)
        self.assertIn("[EMAIL_", r)
        self.assertIn("[PHONE_", r)

    def test_hook_json_full_document(self):
        payload = json.dumps({
            "user": {"name": "Erika Muster", "email": "erika@muster.de"},
            "message": "IBAN: DE75512108001245126199"
        })
        result = process_hook_input(payload)
        data = json.loads(result)
        self.assertNotIn("erika@muster.de", data["user"]["email"])
        self.assertNotIn("DE75512108001245126199", data["message"])

    def test_obfuscated_pii(self):
        """v5.1: Obfuskierte PII werden erkannt"""
        text = "Email: m a x @ t e s t . d e, Tel: 0 9 1 1 1 2 3 4 5 6"
        r = pseudonize(text)
        self.assertIn("[EMAIL_", r)
        self.assertIn("[PHONE_", r)


if __name__ == "__main__":
    verbosity = 2 if "-v" in sys.argv else 1
    unittest.main(verbosity=verbosity)
