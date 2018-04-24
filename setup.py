#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
from setuptools import setup
from setuptools import find_packages


def package_files(directory):
    """
    This function was created to crawl the directory and find files (none python files) using os.walk

    Args:
        directory: path to crawl

    Returns:
        list of package files in an array
    """
    paths = []
    for (path, directories, filenames) in os.walk(directory):
        for filename in filenames:
            paths.append(os.path.join('..', path, filename))
    return paths


setup(
    name="OWASP-Nettacker",
    version='0.0.1',
    description='OWASP Nettacker - Automated Penetration Testing Framework',
    packages=find_packages(),
    # package files + database file
    package_data={"": package_files("web") + ["../api/database.sqlite3"]},
    include_package_data=True,
    install_requires=requirements,
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
    scripts=["scripts/nettacker.bat" if sys.platform == "win32" or sys.platform == "win64"
             else "scripts/nettacker", "nettacker.py"]  # script files for windows and other OS
)
