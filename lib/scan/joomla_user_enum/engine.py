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
import re
import os
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
        "joomla_user_enum_ports": [80, 443]
    }


def joomla_user_enum(target, port, timeout_sec, log_in_file, language, time_sleep,
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
            r = requests.get(target + '/?format=feed')
            joomla_users = list(set(re.findall("<author>(.+?) \((.+?)\)</author>", r.text, re.IGNORECASE)))
            temp_var = []
            for user in joomla_users:
                temp_var.append(user[0] + " " + user[1])
            joomla_users = ', '.join(temp_var)
            if joomla_users != "":
                return joomla_users
            else:
                return False
    except Exception:
        # some error warning
        return False


def __joomla_user_enum(target, port, timeout_sec, log_in_file, language, time_sleep,
                     thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    joomla_users = joomla_user_enum(target, port, timeout_sec, log_in_file, language, time_sleep,
                      thread_tmp_filename, socks_proxy, scan_id, scan_cmd)
    if joomla_users:
        info(messages(language, "found").format(
            target, "Joomla users found ", joomla_users))
        __log_into_file(thread_tmp_filename, 'w', '0', language)
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'joomla_user_enum_scan',
                           'DESCRIPTION': messages(language, "found").format(target, "Joomla users found ", joomla_users), 'TIME': now(),
                           'CATEGORY': "scan",
                           'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
        __log_into_file(log_in_file, 'a', data, language)
        return True
    else:
        return False

@main_function(extra_requirements_dict(), __joomla_user_enum, "joomla_user_enum_scan", "joomla_user_enum_scan")
def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    pass