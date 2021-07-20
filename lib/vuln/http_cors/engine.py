#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Pradeep Jairamani , github.com/pradeepjairamani

import socket
from requests.models import to_native_string
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
from core._time import now
from core.log import __log_into_file
import requests
from core.decor import socks_proxy, main_function


def extra_requirements_dict():
    return {
        "http_cors_vuln_ports": [80, 443]
    }


def http_cors(target, port, timeout_sec, log_in_file, language, time_sleep,
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
            headers = {'Referer': 'http://example.foo/CORSexample1.html', 'Origin': 'http://example.foo',
                       'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:24.0) Gecko/20100101 Firefox/24.0'}
            req = requests.get(target, headers=headers)
            if req.headers['Access-Control-Allow-Origin'] == "*":
                return True
            else:
                return False

    except Exception as e:
        # some error warning
        return False


def __http_cors(target, port, timeout_sec, log_in_file, language, time_sleep,
                thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    if http_cors(target, port, timeout_sec, log_in_file, language, time_sleep,
                 thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
        info(messages(language, "target_vulnerable").format(target, port,
                                                            'Cross Origin Resource Sharing https://www.owasp.org/index.php/Test_Cross_Origin_Resource_Sharing_(OTG-CLIENT-007)'))
        __log_into_file(thread_tmp_filename, 'w', '0', language)
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'http_cors_vuln',
                           'DESCRIPTION': messages(language, "vulnerable").format('Cross Origin Resource Sharing https://www.owasp.org/index.php/Test_Cross_Origin_Resource_Sharing_(OTG-CLIENT-007)'), 'TIME': now(),
                           'CATEGORY': "vuln",
                           'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
        __log_into_file(log_in_file, 'a', data, language)
        return True
    else:
        return False

@main_function(extra_requirements_dict(), __http_cors, "http_cors_vuln", "Cross Origin Resource Sharing")
def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    pass