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
import ssl
from core.alert import *
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.log import __log_into_file
import requests
from core.decor import socks_proxy, main_function

def extra_requirements_dict():
    return {
        "xss_vuln_ports": [80, 443]
    }


def xss_protection(target, port, timeout_sec, log_in_file, language, time_sleep,
                   thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    regex = '1; report='+'https?:\/\/(www\.)?[-a-zA-Z0-9]{1,256}\.[-a-zA-Z0-9]{1,6}'
    try:
        

        from core.conn import connection
        s = connection(target, port, timeout_sec, socks_proxy)
        if not s:
            return False
        else:
            if target_type(target) != "HTTP" and port == 443:
                target = 'https://' + target
            if target_type(target) != "HTTP" and port == 80:
                target = 'http://' + target
            req = requests.get(target)
            try:
                if req.headers['X-XSS-Protection'] == '1; mode=block':
                    return False
                elif req.header['X-XSS-Protection'] == '1':
                    return False
                elif re.match(regex, req.header['X-XSS-Protection']):
                    return False
                else:
                    return True
            except:
                return True
    except Exception as e:
        # some error warning
        return False


def __xss_protection(target, port, timeout_sec, log_in_file, language, time_sleep,
                     thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    if xss_protection(target, port, timeout_sec, log_in_file, language, time_sleep,
                      thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
        info(messages(language, "target_vulnerable").format(target, port,
                                                            'X_XSS_Protection not set properly, This header enables the Cross-site scripting (XSS) filter.'))
        __log_into_file(thread_tmp_filename, 'w', '0', language)
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'XSS_protection_vuln',
                           'DESCRIPTION': messages(language, "vulnerable").format(''), 'TIME': now(),
                           'CATEGORY': "vuln",
                           'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
        __log_into_file(log_in_file, 'a', data, language)
        return True
    else:
        return False

@main_function(extra_requirements_dict(), __xss_protection, "XSS_protection_vuln", "X_XSS_Protection set properly")
def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    pass