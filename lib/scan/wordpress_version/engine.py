#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Pradeep Jairamani , github.com/pradeepjairamani

from core.conn import connection
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
from core import decor
from core.alert import *
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.log import __log_into_file
import requests
from core.decor import main_function, socks_proxy
from core.conn import connection

def extra_requirements_dict():
    return {
        "wordpress_version_ports": [80, 443]
    }


def wordpress_version(target, port, timeout_sec, log_in_file, language, time_sleep,
                      thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    try:
        
        s = connection(target, port, timeout_sec, socks_proxy)

        if not s:
            return False
        else:
            if target_type(target) != "HTTP" and port == 443:
                target = 'https://' + target
            if target_type(target) != "HTTP" and port == 80:
                target = 'http://' + target
            try:
                req = requests.get(target+'/wp-admin/install.php')
            except:
                return False
            try:
                global version
                regex = 'ver=.*\d'
                pattern = re.compile(regex)
                version = re.findall(pattern, req.text)
                version = max(set(version), key=version.count).replace(
                    'ver=', '')
                return True
            except:
                return False
    except Exception as e:
        # some error warning
        return False


def __wordpress_version(target, port, timeout_sec, log_in_file, language, time_sleep,
                        thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    if wordpress_version(target, port, timeout_sec, log_in_file, language, time_sleep,
                         thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
        info(messages(language, "found").format(
            target, "Wordpress Version", version), log_in_file, "a", {'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'wordpress_version_scan',
                           'DESCRIPTION': messages(language, "found").format(target, "wordpress Version", version), 'TIME': now(),
                           'CATEGORY': "vuln",
                           'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}, language, thread_tmp_filename)
        return True
    else:
        return False

@main_function(extra_requirements_dict(), __wordpress_version, "wordpress_version_scan", "wordpress_version_scan")
def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    pass