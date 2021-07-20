#!/usr/bin/env python3
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
from core.decor import socks_proxy, main_function



def extra_requirements_dict():
    return {
        "Proftpd_vuln_ports": [21, 990]
    }


def directory_traversal(target, port, timeout_sec, log_in_file, language, time_sleep,
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
                vuln_list = ["1.2.10rc2", "1.2.10rc3", "1.2.10", "1.3.0rc2", "1.3.0rc3", "1.3.0rc4", "1.3.0rc5", "1.3.0", "1.3.0rc1", "1.3.0a", "1.3.1rc1", "1.3.1rc2", "1.3.1rc3", "1.3.1", "1.3.2rc3",
                             "1.3.2", "1.3.2d", "1.3.2rc4", "1.3.2E", "1.3.2rc2", "1.3.2rc1", "1.3.2b", "1.3.2a", "1.3.2c", "1.3.3", "1.3.3a", "1.3.3b", "1.3.3rc2", "1.3.3rc1", "1.3.3rc3", "1.3.3rc4"]
                if banner[2] in vuln_list:
                    return True
                else:
                    return False
            else:
                return False
    except Exception as e:
        # some error warning
        return False


def __directory_traversal(target, port, timeout_sec, log_in_file, language, time_sleep,
                          thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    if directory_traversal(target, port, timeout_sec, log_in_file, language, time_sleep,
                           thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
        info(messages(language, "target_vulnerable").format(target, port, 'Multiple directory traversal vulnerabilities in the mod_site_misc module in ProFTPD before 1.3.3c allow remote authenticated users to create directories, delete directories, create symlinks, and modify file timestamps via directory traversal sequences in a (1) SITE MKDIR, (2) SITE RMDIR, (3) SITE SYMLINK, or (4) SITE UTIME command.	CVE-2010-3867'))
        __log_into_file(thread_tmp_filename, 'w', '0', language)
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'Proftpd_directory_traversal_vuln',
                           'DESCRIPTION': messages(language, "vulnerable").format('Multiple directory traversal vulnerabilities in the mod_site_misc module in ProFTPD before 1.3.3c allow remote authenticated users to create directories, delete directories, create symlinks, and modify file timestamps via directory traversal sequences in a (1) SITE MKDIR, (2) SITE RMDIR, (3) SITE SYMLINK, or (4) SITE UTIME command.	CVE-2010-3867'), 'TIME': now(),
                           'CATEGORY': "vuln",
                           'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
        __log_into_file(log_in_file, 'a', data, language)
        return True
    else:
        return False

@main_function(extra_requirements_dict(), __directory_traversal, "Proftpd_directory_traversal_vuln", "ProFTPd_directory_traversal CVE-2010-3867")
def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    pass