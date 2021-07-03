#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Pradeep Jairamani , github.com/pradeepjairamani

import socket
import socks
import time
import json
import threading
import string
import random
import sys
import re
import os
from OpenSSL import crypto
import ssl
from core.alert import *
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.decor import socks_proxy, main_function
from core.log import __log_into_file


def extra_requirements_dict():
    return {
        "bftpd_vuln_ports": [21, 990]
    }
def remote_dos(target, port, timeout_sec, log_in_file, language, time_sleep,
               thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    try:
        from core.conn import connection
        s = connection(target, port, timeout_sec, socks_proxy)
        if not s:
            return False
        else:
            s.send("ehlo")
            banner = s.recv(100)
            banner = banner.split(" ")
            if banner[1] == "bftpd":
                version = banner[2]
                if re.search("\d.\d.\d", version):
                    version, sep, tail = version.rpartition(".")
                else:
                    pass
                if float(version) < 4.7:
                    return True
                else:
                    return False
            else:
                return False
    except Exception as e:
        # some error warning
        return False


def __remote_dos(target, port, timeout_sec, log_in_file, language, time_sleep,
                 thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    if remote_dos(target, port, timeout_sec, log_in_file, language, time_sleep,
                  thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
        info(messages(language, "target_vulnerable").format(target, port,
                                                            'Bftpd is prone to an unspecified remote denial-of-service vulnerability.  CVE-2009-4593'))
        __log_into_file(thread_tmp_filename, 'w', '0', language)
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'Bftpd_remote_dos_vuln',
                           'DESCRIPTION': messages(language, "vulnerable").format('Bftpd is prone to an unspecified remote denial-of-service vulnerability.  CVE-2009-4593'), 'TIME': now(),
                           'CATEGORY': "vuln",
                           'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
        __log_into_file(log_in_file, 'a', data, language)
        return True
    else:
        return False

@main_function(extra_requirements_dict(), __remote_dos, "Bftpd_remote_dos_vuln", "Bftpd_remote_dos CVE-2009-4593")
def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    pass