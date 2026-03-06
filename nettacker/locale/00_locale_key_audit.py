import yaml
import os
import sys
import re

BASE_FILE = "en.yaml"
REPORT_FILE = "00_locale_missing_keys_report.txt"
PLACEHOLDER_COMMENT = "# Auto-inserted keys with placeholder values, fix before committing\n"

def print_help():
    print("""
Usage: python 00_locale_key_audit.py [LANGUAGES] [--fix]

LANGUAGES:
  Specify which language YAML files to check.
  - Single: bn, fr, ar
  - Multiple: bn AND fr, bn & ar
  - All languages: all (or leave blank)

--fix
  Insert missing keys with placeholder values at the end of the YAML.

Notes:
  - Compares against en.yaml as reference.
  - Placeholders must be translated manually.
  - No automatic translation is performed.
""")
    sys.exit()

def normalize_filename(name):
    if not name.endswith(".yaml"):
        name += ".yaml"
    return name

def parse_languages(args):
    if not args or args[0].lower() == "all":
        return "all"

    text = " ".join([a for a in args if a.lower() != "--fix"])
    if not text:
        return "all"

    langs = re.split(r"\s*(?:&|AND)\s*", text, flags=re.IGNORECASE)
    return [normalize_filename(lang.strip()) for lang in langs]

if "-h" in sys.argv or "--help" in sys.argv:
    print_help()

FIX_MODE = "--fix" in sys.argv

languages = parse_languages(sys.argv[1:])

with open(BASE_FILE, "r", encoding="utf-8") as f:
    base_data = yaml.safe_load(f)

base_keys = set(base_data.keys())

available_files = [
    f for f in os.listdir(".")
    if f.endswith(".yaml") and f != BASE_FILE
]

if languages == "all":
    target_files = sorted(available_files)
else:
    target_files = []
    for lang in languages:
        if lang not in available_files:
            print(f"Error: '{lang}' does not exist in this directory.")
            sys.exit()
        target_files.append(lang)

report_lines = []

for file in target_files:

    with open(file, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    file_keys = set(data.keys())
    missing_keys = base_keys - file_keys

    if not missing_keys:
        print(f"{file} is up to date in reference to en.yaml")
        continue

    report_lines.append(f"{file} is missing:\n")
    for key in sorted(missing_keys):
        value = base_data[key]
        report_lines.append(f"{key}:")
        report_lines.append(f'  "{value}"\n')

    if FIX_MODE:
        with open(file, "a", encoding="utf-8") as f:
            f.write("\n\n")
            f.write(PLACEHOLDER_COMMENT)
            for key in sorted(missing_keys):
                f.write(f'{key}: "placeholder_value"\n')

    report_lines.append("\n" + "-" * 40 + "\n")

if report_lines:
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))
    print(f"\nReport generated: {REPORT_FILE}")
    if FIX_MODE:
        print("Missing keys were also appended to the respective YAML files with placeholders.")
else:
    print("\nNo missing keys found. No report generated.")