#!/usr/bin/env python3
"""
Usage:
    ./sync.py en.yaml locale_folder

Description:
  1. Reads in en.yaml as the reference file.
  2. Scans the specified folder for YAML files (except en.yaml).
  3. For each locale file, generates a new YAML file with keys in the order of en.yaml.
     If a key exists in the locale file, its value is used; otherwise, the value from en.yaml is used.
  4. The output preserves original formatting, including quotes and backslashes,
     and prevents automatic line wrapping.
"""

import sys
import os
from ruamel.yaml import YAML

if len(sys.argv) != 3:
    print("Usage: {} en.yaml locale_folder".format(sys.argv[0]))
    sys.exit(1)

en_file = sys.argv[1]
locale_folder = sys.argv[2]

yaml = YAML()
yaml.preserve_quotes = True  # Preserve original quotes
yaml.width = 4096            # Set a large width to avoid automatic line wrapping

# Load the English reference file
with open(en_file, 'r', encoding='utf-8') as f:
    en_data = yaml.load(f)

# Process all .yaml files in the folder except the English file
for filename in os.listdir(locale_folder):
    if not filename.endswith('.yaml'):
        continue
    if filename == os.path.basename(en_file):
        continue

    target_path = os.path.join(locale_folder, filename)
    output_path = os.path.join(locale_folder, filename)

    # Load the target locale file
    with open(target_path, 'r', encoding='utf-8') as f:
        target_data = yaml.load(f)

    # Build a new dictionary following the order of keys in en.yaml
    new_data = {}
    for key in en_data:
        if key in target_data:
            new_data[key] = target_data[key]
        else:
            new_data[key] = en_data[key]

    # Output the result to a new file
    with open(output_path, 'w', encoding='utf-8') as f:
        yaml.dump(new_data, f)

    print("Updated file has been output to", output_path)
