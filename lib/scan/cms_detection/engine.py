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
from lib.payload.wordlists import useragents



USER_AGENT = {'User-agent': random.choice(useragents.useragents())}


def extra_requirements_dict():
    return {
        "cms_detection_ports": [80,443]
    }




def cms_detection(target, port, timeout_sec, log_in_file, language, time_sleep,
                   thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    try:
        try:
        
            from core.conn import connection
            s = connection(target, port, timeout_sec, socks_proxy)    

        except Exception:
            return False
        if not s:
            return False
        else:
            global cms_name
            if target_type(target) != "HTTP" and port == 443:
                target = 'https://' + target
            if target_type(target) != "HTTP" and port == 80:
                target = 'http://' + target
            req_url = target + "/N0WH3R3.php"
            req_joomla_url = target + "/configuration.php"           
            req_wordpress_url = target + "/wp-config.php"
            req_drupal_url = target + "/sites/default/settings.php"
            try:
               
               req = requests.get(req_url, timeout=10, headers=USER_AGENT)
               code_for_404 = req.text
               req_wordpress = requests.get(req_wordpress_url, timeout=10, headers=USER_AGENT)
               req_joomla = requests.get(req_joomla_url, timeout=10, headers=USER_AGENT)
               req_drupal = requests.get(req_drupal_url, timeout=10, headers=USER_AGENT)
            except requests.exceptions.RequestException: 
               return False
            if req_wordpress.text != code_for_404 or req_wordpress.status_code == 403:
                cms_name = "Wordpress"
                return True
            elif req_drupal.status_code != code_for_404 or req_drupal.status_code == 403:
                cms_name = "Drupal"
                return True
            elif req_joomla.status_code != code_for_404 or req_joomla.status_code == 403:
                cms_name = "Joomla"
                return True
            else:
                return False
    except Exception:
        return False


def __cms_detection(target, port, timeout_sec, log_in_file, language, time_sleep,
                     thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    if cms_detection(target, port, timeout_sec, log_in_file, language, time_sleep,
                      thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
        info(messages(language, "found").format(target, "CMS Name", cms_name))
        __log_into_file(thread_tmp_filename, 'w', '0', language)
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'cms_detection_scan',
                           'DESCRIPTION': messages(language, "found").format(target, "CMS Name", cms_name), 'TIME': now(),
                           'CATEGORY': "scan",
                           'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
        __log_into_file(log_in_file, 'a', data, language)
        return True
    else:
        return False


@main_function(extra_requirements_dict(), __cms_detection, "cms_detection_scan", "cms_detection_scan")
def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    pass