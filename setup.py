#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from setuptools import setup
from setuptools import find_packages

setup(
    name="OWASP-Nettacker",
    version='0.0.1',
    description='OWASP Nettacker - Automated Penetration Testing Framework',
    packages=find_packages(),
    include_package_data=True,
    install_requires=open("requirements.txt").read().rsplit(),
    url="https://github.com/viraintel/OWASP-Nettacker",
    license="Apache-2.0",
    author="Ali Razmjoo",
    author_email="ali.razmjoo@owasp.org",
    long_description="Automated Penetration Testing Framework - OWASP Nettacker project is created to"
                     " automate information gathering, vulnerability scanning and eventually generating"
                     " a report for networks, including services, bugs, vulnerabilities, misconfigurations,"
                     " and other information. This software will utilize TCP SYN, ACK, ICMP and many other"
                     " protocols in order to detect and bypass Firewall/IDS/IPS devices. By leveraging a"
                     " unique method in OWASP Nettacker for discovering protected services and devices such"
                     " as SCADA. It would make a competitive edge compared to other scanner making it one of"
                     " the bests.",
    package_data={"": ["*.txt", "*.md", "*.css", "*.js", "*.html", "*.htm", ".png"]},
    scripts=["scripts/nettacker.bat" if sys.platform == "win32" or sys.platform == "win64"
             else "scripts/nettacker", "nettacker.py"]
)
