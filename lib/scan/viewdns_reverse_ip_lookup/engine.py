#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import time
import json
import threading
import string
import random
import ssl
from xml.etree import ElementTree as ET
import os
from core.alert import *
from core.targets import target_type
from core.targets import target_to_host
from lib.icmp.engine import do_one as do_one_ping
import requests
import random


def extra_requirements_dict():
    return {}


def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep,
          language, verbose_level, show_version, check_update, proxies, retries, ping_flag,
          methods_args):  # Main function
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(target) != 'HTTP':
        # output format
        _HOST = messages(language, 53)
        _USERNAME = messages(language, 54)
        _PASSWORD = messages(language, 55)
        _PORT = messages(language, 56)
        _TYPE = messages(language, 57)
        _DESCRIPTION = messages(language, 58)
        port = ""
        time.sleep(time_sleep)

        # set user agent
        headers = {"User-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0",
                   "Accept": "text/javascript, text/html, application/xml, text/xml, */*",
                   "Accept-Language": "en-US,en;q=0.5"
                   }
        # timeout check
        if ping_flag and do_one_ping(target_to_host(target), timeout_sec, 8) is None:
            warn(messages(language, 100).format(target_to_host(target), 'viewdns_reverse_ip_lookup_scan'))
            return None
        total_req = 1
        trying = 1
        info(messages(language, 113).format(trying, total_req, num, total, target))
        n = 0
        while 1:
            try:
                res = requests.get('http://viewdns.info/reverseip/?host={0}&t=1'.format(target), timeout=timeout_sec,
                                   headers=headers, verify=True).text
                break
            except:
                n += 1
                if n is retries:
                    warn(messages(language, 106).format("viewdns.info"))
                    return 1
        s = '<table>' + res.rsplit('''<table border="1">''')[1].rsplit("<br></td></tr><tr></tr>")[0]
        _values = []
        table = ET.XML(s)
        rows = iter(table)
        headers = [col.text for col in next(rows)]
        for row in rows:
            values = [col.text for col in row]
            _values.append(dict(zip(headers, values))["Domain"])
        info(messages(language, 114).format(len(_values), ", ".join(_values) if len(_values) > 0 else "None"))
        if len(_values) > 0:
            save = open(log_in_file, 'a')
            save.write(json.dumps(
                {_HOST: target, _USERNAME: '', _PASSWORD: '', _PORT: '', _TYPE: 'viewdns_reverse_ip_lookup_scan',
                 _DESCRIPTION: messages(language, 114).format(len(_values), ", ".join(_values) if len(
                     _values) > 0 else "None")}) + '\n')
            save.close()
        if verbose_level is not 0:
            save = open(log_in_file, 'a')
            save.write(json.dumps(
                {_HOST: target, _USERNAME: '', _PASSWORD: '', _PORT: '', _TYPE: 'viewdns_reverse_ip_lookup_scan',
                 _DESCRIPTION: messages(language, 114).format(len(_values), ", ".join(_values) if len(
                     _values) > 0 else "None")}) + '\n')
            save.close()
    else:
        warn(messages(language, 69).format('viewdns_reverse_ip_lookup_scan', target))
