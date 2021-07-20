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
import spf
from core.compatible import version
from core.decor import socks_proxy, main_function


def extra_requirements_dict():
    return {
        "joomla_version_ports": [80, 443]
    }


def joomla_version(target, port, timeout_sec, log_in_file, language, time_sleep,
                   thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    try:
        

        from core.conn import connection
        s = connection(target, port, timeout_sec, socks_proxy)
        if not s:
            return False
        else:
            try:
                global result
                host_ip = socket.gethostbyname(target)
                result = spf.check2(host_ip,"admin@"+target, target)
                return True
            except:
                return False
    except Exception as e:
        return False


def __joomla_version(target, port, timeout_sec, log_in_file, language, time_sleep,
                     thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    if joomla_version(target, port, timeout_sec, log_in_file, language, time_sleep,
                      thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
        info(messages(language, "found").format(
            target, "Sender Policy Framework Record : "+ result[0], " " + result[1]))
        __log_into_file(thread_tmp_filename, 'w', '0', language)
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'joomla_version_scan',
                           'DESCRIPTION': messages(language, "found").format(target, "Sender Policy Framework Record : "+ result[0], " " + result[1]), 'TIME': now(),
                           'CATEGORY': "scan",
                           'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
        __log_into_file(log_in_file, 'a', data, language)
        return True
    else:
        return False

@main_function(extra_requirements_dict(), __joomla_version, "joomla_version_scan", "joomla_version_scan")
def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    pass