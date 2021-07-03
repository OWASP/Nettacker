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
import os
from core.alert import *
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.log import __log_into_file
from core.decor import main_function, socks_proxy
import requests


def extra_requirements_dict():
    return {
        "xdebug_vuln_ports": [80, 443]
    }


def xdebug(target, port, timeout_sec, log_in_file, language, time_sleep,
                 thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
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
                if req.headers['Xdebug'] == '2.5.5':
                    return True
                else:
                    return False
            except Exception:
                return False
    except Exception:
        # some error warning
        return False


def __xdebug(target, port, timeout_sec, log_in_file, language, time_sleep,
                   thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    if xdebug(target, port, timeout_sec, log_in_file, language, time_sleep,
                    thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
        info(messages(language, "target_vulnerable").format(target, port,
                                                            'Xdebug Vulnerability - Module exploits a vulnerability in the eval command present in Xdebug versions 2.5.5 and below. This allows the attacker to execute arbitrary php code as the context of the web user.'))
        __log_into_file(thread_tmp_filename, 'w', '0', language)
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'xdebug_vuln',
                           'DESCRIPTION': messages(language, "vulnerable").format('Xdebug Vulnerability - Module exploits a vulnerability in the eval command present in Xdebug versions 2.5.5 and below. This allows the attacker to execute arbitrary php code as the context of the web user.'), 'TIME': now(),
                           'CATEGORY': "vuln",
                           'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
        __log_into_file(log_in_file, 'a', data, language)
        return True
    else:
        return False

@main_function(extra_requirements_dict(), __xdebug, "xdebug_vuln", "xdebug")
def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    pass