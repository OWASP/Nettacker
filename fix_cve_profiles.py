#!/usr/bin/env python3
"""
Fix inconsistent CVE profile tags in Nettacker module files.

Issue #1572: Inconsistency in Profiles across modules
- Some use cve_<year>, others cve-<year>, most use cve<year>
- Some missing CVE tag entirely
- Standard: cve_<year> (e.g., cve_2021)
"""

import os
import re
import yaml
from pathlib import Path

MODULES_DIR = Path("nettacker/modules/vuln")

# Pattern to extract year from CVE references in description/reference
CVE_PATTERN = re.compile(r'CVE-(\d{4})-\d+')

def extract_cve_years(content):
    """Extract all CVE years from description and reference fields."""
    years = set()
    for match in CVE_PATTERN.finditer(content):
        years.add(match.group(1))
    return years

def get_existing_cve_profiles(profiles):
    """Find existing CVE-related profiles."""
    cve_profiles = []
    for p in profiles:
        if p.startswith('cve'):
            cve_profiles.append(p)
    return cve_profiles

def standardize_cve_profile(year):
    """Return standardized CVE profile for a year."""
    return f"cve_{year}"

def process_file(filepath):
    """Process a single YAML module file."""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    data = yaml.safe_load(content)
    if not data or 'info' not in data:
        return False, "No info section"
    
    info = data.get('info', {})
    profiles = info.get('profiles', [])
    if not profiles:
        return False, "Empty profiles"
    
    # Extract CVE years from description/reference
    desc = info.get('description', '') or ''
    refs = info.get('reference', [])
    if isinstance(refs, list):
        ref_text = ' '.join(refs)
    else:
        ref_text = str(refs)
    
    all_text = desc + ' ' + ref_text
    cve_years = extract_cve_years(all_text)
    
    # Also check filename for CVE year
    filename = filepath.name
    filename_years = re.findall(r'cve[_-]?(\d{4})[_-]', filename, re.IGNORECASE)
    for y in filename_years:
        cve_years.add(y)
    
    # Get existing CVE profiles
    existing_cve = get_existing_cve_profiles(profiles)
    
    # Determine target CVE profiles
    target_cve_profiles = set()
    for year in sorted(cve_years):
        target_cve_profiles.add(standardize_cve_profile(year))
    
    # If no CVE years found but has existing CVE profiles, keep those (standardized)
    if not target_cve_profiles and existing_cve:
        for p in existing_cve:
            # Try to extract year from existing profile
            m = re.search(r'cve[_-]?(\d{4})', p)
            if m:
                target_cve_profiles.add(standardize_cve_profile(m.group(1)))
            else:
                target_cve_profiles.add('cve')  # generic fallback
    
    # Remove old CVE profiles
    new_profiles = [p for p in profiles if not p.startswith('cve')]
    
    # Add standardized CVE profiles
    for cp in sorted(target_cve_profiles):
        if cp not in new_profiles:
            new_profiles.append(cp)
    
    # Check if anything changed
    if new_profiles == profiles:
        return False, "No changes needed"
    
    # Update data
    info['profiles'] = new_profiles
    data['info'] = info
    
    # Write back preserving formatting as much as possible
    with open(filepath, 'w', encoding='utf-8') as f:
        yaml.dump(data, f, sort_keys=False, default_flow_style=False, allow_unicode=True)
    
    return True, f"Updated: {existing_cve} -> {sorted(target_cve_profiles)}"

def main():
    files = sorted(MODULES_DIR.glob("*.yaml"))
    print(f"Processing {len(files)} module files...")
    
    changed = 0
    for filepath in files:
        try:
            modified, msg = process_file(filepath)
            if modified:
                print(f"  [OK] {filepath.name}: {msg}")
                changed += 1
            else:
                print(f"  [--] {filepath.name}: {msg}")
        except Exception as e:
            print(f"  [ERR] {filepath.name}: ERROR - {e}")
    
    print(f"\nDone. Modified {changed} files.")

if __name__ == "__main__":
    main()