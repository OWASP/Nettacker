#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from distutils.core import setup

setup(
    install_requires=['netaddr', 'dnspython', 'requests', 'paramiko', 'texttable', 'PySocks', 'win_inet_pton'],
    name='OWASP-Nettacker',
    version='0.1 Beta',
    packages=['lib', 'lib.scan', 'lib.scan.port', 'lib.brute', 'lib.brute.ftp', 'lib.brute.ssh', 'lib.brute.http',
              'lib.brute.smtp', 'lib.sublist3r.subbrute', 'core', 'scripts'],
    url='https://github.com/viraintel/OWASP-Nettacker',
    license='GNU General Public License v3.0',
    author='Ali Razmjoo',
    author_email='ali.razmjoo@owasp.org',
    description='Automated Penetration Testing Framework',
    long_description='Nettacker project was created to automated for information gathering'
                     ' vulnerability scanning and eventually generating report for networks,'
                     ' including services, bugs, vulnerabilities, misconfigurations and information.'
                     ' This software is able to use SYN, ACK, TCP, ICMP and many other protocols to'
                     ' detect and bypass the Firewalls/IDS/IPS and devices. By using a unique solution'
                     ' in Nettacker to find protected services such as SCADA We could make a point to be one of'
                     ' the bests of scanners.',
    scripts=['scripts/nettacker.bat' if sys.platform == 'win32' or sys.platform == 'win64' else 'scripts/nettacker',
             'nettacker.py']
)
