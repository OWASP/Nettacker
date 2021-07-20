#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Aman Gupta , github.com/aman566

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
import requests
from core.decor import main_function, socks_proxy

def extra_requirements_dict():
    return {
        "http_cookie_vuln_ports": [443]
    }

def http_cookie(target, port, timeout_sec, log_in_file, language, time_sleep,
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
            value = req.headers['Set-Cookie'].lower()
            if "samesite" in value:
                return False
            else:
                return True

    except Exception as e:
        return False


def __http_cookie(target, port, timeout_sec, log_in_file, language, time_sleep,
                thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    if http_cookie(target, port, timeout_sec, log_in_file, language, time_sleep,
                 thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
        info(messages(language, "target_vulnerable").format(target, port,
                                                            'Samesite cookie flag should be presen inside Set-Cookie header for preventing CSRF attacks'))
        __log_into_file(thread_tmp_filename, 'w', '0', language)
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'http_cookie_vuln',
                           'DESCRIPTION': messages(language, "vulnerable").format('Samesite cookie flag should be presen inside Set-Cookie header for preventing CSRF attacks'), 'TIME': now(),
                           'CATEGORY': "vuln",
                           'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
        __log_into_file(log_in_file, 'a', data, language)
        return True
    else:
        return False

@main_function(extra_requirements_dict(), __http_cookie, "http_cookie_vuln", "Set-Cookie")
def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    pass