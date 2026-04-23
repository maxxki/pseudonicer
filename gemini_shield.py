#!/usr/bin/env python3
import sys
import os
import subprocess

# Stellt sicher, dass das Script sein Hauptmodul findet, auch wenn man es global aufruft
sys.path.append(os.path.dirname(__file__))

try:
    from maxxki_pseudonicer import process_hook_input
except ImportError:
    print("❌ Fehler: maxxki_pseudonicer.py muss im selben Verzeichnis liegen!")
    sys.exit(1)

def main():
    # 1. Stdin/Argv Automatik (wie besprochen)
    if not sys.stdin.isatty():
        raw_input = sys.stdin.read()
    else:
        raw_input = " ".join(sys.argv[1:])

    if not raw_input.strip():
        # Kleiner Hilfe-Text für dich im Terminal
        print("Usage: gshield 'Mein Prompt mit PII'  ODER  cat data.log | gshield")
        sys.exit(0)

    # 2. Deine Logik (inkl. JSON-Detection und Context-Hints)
    safe_text = process_hook_input(raw_input)

    # 3. Ab zu Gemini
    # Hier setzt du einfach den Befehl ein, den du im Terminal für Gemini nutzt.
    # Falls dein Tool Argumente wie '--prompt' braucht, einfach hier anpassen.
    try:
        # Beispiel für einen Standard-CLI-Aufruf:
        subprocess.run(["gemini", "ask", safe_text], check=True)
    except FileNotFoundError:
        print("\n❌ Gemini CLI nicht gefunden. Pfad in 'gemini_shield.py' prüfen.")
    except KeyboardInterrupt:
        print("\nAbgebrochen.")
    except Exception as e:
        print(f"\n❌ Fehler: {e}")

if __name__ == "__main__":
    main()
