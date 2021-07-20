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
from core.decor import socks_proxy, main_function


def extra_requirements_dict():
    return {
        "SSL_certificate_vuln_ports": [21, 25, 110, 143, 443, 587, 990, 1080, 8080]
    }



def Expired(target, port, timeout_sec, log_in_file, language, time_sleep,
            thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    try:
        

        from core.conn import connection
        s = connection(target, port, timeout_sec, socks_proxy)
        if not s:
            return False
        else:
            cert = ssl.get_server_certificate((target, port))
            x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
            if(x509.has_expired() == True):
                return True
            else:
                return False
    except Exception as e:
        # some error warning
        return False


def __ssl_certificate(target, port, timeout_sec, log_in_file, language, time_sleep,
                      thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    if Expired(target, port, timeout_sec, log_in_file, language, time_sleep,
               thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
        info(messages(language, "target_vulnerable").format(
            target, port, 'SSL Certificate has Expired'))
        __log_into_file(thread_tmp_filename, 'w', '0', language)
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'ssl_certificate_expired_vuln',
                           'DESCRIPTION': messages(language, "vulnerable").format('SSL Certificate has Expired'), 'TIME': now(),
                           'CATEGORY': "vuln",
                           'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
        __log_into_file(log_in_file, 'a', data, language)
        return True
    else:
        return False

@main_function(extra_requirements_dict(), __ssl_certificate, "ssl_certificate_expired_vuln", "SSL Certificate is not Expired")
def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    pass