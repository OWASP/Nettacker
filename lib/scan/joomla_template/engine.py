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
from core.decor import main_function, socks_proxy



def extra_requirements_dict():
    return {
        "joomla_template_ports": [80, 443]
    }





def joomla_template(target, port, timeout_sec, log_in_file, language, time_sleep,
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
            r = requests.get(target, verify = False) 
            r2 = requests.get(target+'/administrator/', verify = False)
            try:
                global web_template
                global admin_template
                web_template = ''.join(set(re.findall("/templates/(.+?)/", r.text, re.IGNORECASE)))
                admin_template = ''.join(set(re.findall("/administrator/templates/(.+?)/", r2.text, re.IGNORECASE)))
                if web_template != "" or admin_template != "":
                    return True
                else:
                    return False
            except:
                return False
    except Exception as e:
        # some error warning
        return False


def __joomla_template(target, port, timeout_sec, log_in_file, language, time_sleep,
                     thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    if joomla_template(target, port, timeout_sec, log_in_file, language, time_sleep,
                      thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
        info(messages(language, "found").format(
            target, "Template Found", " Web Template : " +web_template + ", Admin Template : " + admin_template))
        __log_into_file(thread_tmp_filename, 'w', '0', language)
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'joomla_template',
                           'DESCRIPTION': messages(language, "found").format(target, "Web Template and Admin Template Found", web_template + " " + admin_template), 'TIME': now(),
                           'CATEGORY': "scan",
                           'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
        __log_into_file(log_in_file, 'a', data, language)
        return True
    else:
        return False

@main_function(extra_requirements_dict(), __joomla_template, "joomla_template", "joomla_template")
def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    pass