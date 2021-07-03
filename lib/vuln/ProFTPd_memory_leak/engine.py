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
import struct
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
from core.log import __log_into_file


def extra_requirements_dict():
    return {
        "Proftpd_vuln_ports": [21, 990]
    }


from core.decor import main_function, socks_proxy



def memory_leak(target, port, timeout_sec, log_in_file, language, time_sleep,
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
            if banner[1] == "Proftpd":
                if banner[2] == "1.2.0rc2":
                    return True
                else:
                    return False
            else:
                return False
    except Exception as e:
        # some error warning
        return False


def __memory_leak(target, port, timeout_sec, log_in_file, language, time_sleep,
                    thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    if memory_leak(target, port, timeout_sec, log_in_file, language, time_sleep,
                     thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
        info(messages(language, "target_vulnerable").format(target, port,
                                                            'Memory leak in ProFTPd 1.2.0rc2 allows remote attackers to cause a denial of service via a series of USER commands, and possibly SIZE commands if the server has been improperly installed.    CVE-2001-0136'))
        __log_into_file(thread_tmp_filename, 'w', '0', language)
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'ProFTPd_memory_leak_vuln',
                           'DESCRIPTION': messages(language, "vulnerable").format('Memory leak in ProFTPd 1.2.0rc2 allows remote attackers to cause a denial of service via a series of USER commands, and possibly SIZE commands if the server has been improperly installed.  CVE-2001-0136'), 'TIME': now(),
                           'CATEGORY': "vuln",
                           'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
        __log_into_file(log_in_file, 'a', data, language)
        return True
    else:
        return False

@main_function(extra_requirements_dict(), __memory_leak, "ProFTPd_memory_leak_vuln", "ProFTPd_memory_leak  CVE-2001-0136")
def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    pass