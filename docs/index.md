# OWASP Nettacker Documentation

This documentation is generated using [mkdocs.org](https://www.mkdocs.org) and [Material for MkDocs theme](https://github.com/squidfunk/mkdocs-material)


## Nettacker

OWASP Nettacker is an automated penetration testing framework designed to help cyber security professionals and ethical hackers perform reconnaissance, vulnerability assessments, and network security audits efficiently. Nettacker automates information gathering, vulnerability scanning, and credential brute forcing tasks, making it a powerful tool for identifying weaknesses in networks, web applications, IoT devices and APIs.

Documentation [Home](Home.md)

## 🔧 Quick Start

Here are some common usage examples to help you get started with OWASP Nettacker:

```bash
# Basic port scan on a public target
python nettacker.py -i scanme.nmap.org -m port_scan

# Run all modules on a local IP
python nettacker.py -i 192.168.1.1 --modules all

# Scan using a built-in profile
python nettacker.py -i example.com --profile scan -v

# Save results as JSON with graph output
python nettacker.py -i example.com -m port_scan -o results.json --graph d3_tree

# Scan multiple targets listed in a file
python nettacker.py -T targets.txt -m subdomain_scan
Use --help to explore more flags:

bash
Copy
Edit
python nettacker.py --help
Nettacker is fully modular — customize scans using config files, profiles, or manual flags.

yaml
Copy
Edit

---

## 📍 Where to Put This in `index.md`

- Ideally after the introduction or before the long table of flags/config
- Or at the very top if there’s no content yet
- You can add a new heading like:

```md
# Nettacker Documentation
Welcome to OWASP Nettacker...

## 🔧 Quick Start
...
