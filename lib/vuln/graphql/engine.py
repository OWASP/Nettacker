#!/usr/bin/env python3
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
from lib.payload.wordlists.graphql import graphql_list
from lib.payload.wordlists.useragents import useragents
from core.decor import socks_proxy, main_function


def extra_requirements_dict():
    return {
        "graphql_vuln_ports": [80, 443]
    }

def graphql(target, port, timeout_sec, socks_proxy):
    try:
        
        from core.conn import connection
        s = connection(target_to_host(target), port, timeout_sec, socks_proxy)
        if not s:
            return False
        else:
            if target_type(target) != "HTTP" and port == 443:
                target = 'https://' + target
            if target_type(target) != "HTTP" and port == 80:
                target = 'http://' + target

            headers = {
                "User-Agent": random.choice(useragents()),
                "Accept": "text/html,application/xhtml+xml,application/xml; q=0.9,image/webp,image/apng,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
            }
            query = """{
                __schema {
                    types {
                    name
                    }
                }
                }
            """
            params = {"query":query, "variables":"{}"}
            tempTarget = target
            global final_endpoint
            final_endpoint = ''
            for endpoint in graphql_list():
                tempTarget += endpoint
                try:
                    req = requests.post(tempTarget, json=params, headers=headers, verify=False, timeout=timeout_sec)
                    tempTarget = target
                except Exception:
                    return False
                else:
                    if req.status_code == 200:
                        json_data = json.loads(req.text)
                        if json_data.get('data') or json_data.get('errors'):
                            return True

            return False
    except Exception:
        # some error warning
        return False


def __graphql(target, port, timeout_sec, log_in_file, language, time_sleep,
                   thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    if graphql(target, port, timeout_sec, socks_proxy):
        info(messages(language, "graphql_inspection").format(target, port))
        __log_into_file(thread_tmp_filename, 'w', '0', language)
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'graphql_vuln',
                           'DESCRIPTION': messages(language, "graphql_inspection_console").format(final_endpoint), 'TIME': now(),
                           'CATEGORY': "vuln",
                           'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
        __log_into_file(log_in_file, 'a', data, language)
        return True
    else:
        return False

@main_function(extra_requirements_dict(), __graphql, "graphql_vuln", "graphql_console_not_found")
def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    pass