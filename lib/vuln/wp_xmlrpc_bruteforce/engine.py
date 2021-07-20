#!/usr/bin/env python3
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
from core.alert import *
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.decor import main_function, socks_proxy
from core.log import __log_into_file
import requests
from core.conn import connection


def extra_requirements_dict():
    return {
        "xmlrpc_bruteforce_vuln_ports": [80, 443]
    }


def xmlrpc_bruteforce(target, port, timeout_sec, log_in_file, language, time_sleep,
                 thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    try:
        

        from core.conn import connection
        s = connection(target, port, timeout_sec, socks_proxy)
        if not s:
            return False
        else:
            headers = {}
            if target_type(target) != "HTTP" and port == 443:
                target = 'https://' + target
            if target_type(target) != "HTTP" and port == 80:
                target = 'http://' + target
            headers['Content-Type'] ='text/xml'
            postdata = '''<methodCall><methodName>wp.getUsersBlogs</methodName><params>
                            <param><value><string>admin</string></value></param>
                            <param><value><string></string></value></param>
                            </params></methodCall>'''
            req = requests.post(target+'/xmlrpc.php', data = postdata, headers = headers)
            if re.search('<int>403</int>',req.text):
                return True
            else:
                return False
    except Exception as e:
        return False


def __xmlrpc_bruteforce(target, port, timeout_sec, log_in_file, language, time_sleep,
                   thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    if xmlrpc_bruteforce(target, port, timeout_sec, log_in_file, language, time_sleep,
                    thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
        info(messages(language, "target_vulnerable").format(target, port,
                                                            'Wordpress_xmlrpc_bruteforce'))
        __log_into_file(thread_tmp_filename, 'w', '0', language)
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'xmlrpc_bruteforce_vuln',
                           'DESCRIPTION': messages(language, "vulnerable").format('Wordpress_xmlrpc_bruteforce'), 'TIME': now(),
                           'CATEGORY': "vuln",
                           'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
        __log_into_file(log_in_file, 'a', data, language)
        return True
    else:
        return False

@main_function(extra_requirements_dict(), __xmlrpc_bruteforce, "xmlrpc_bruteforce_vuln", "Wordpress_xmlrpc_bruteforce")
def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    pass