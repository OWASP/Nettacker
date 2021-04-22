#!/usr/bin/env python
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
from lib.payload.wordlists import useragents


def extra_requirements_dict():
    return {
        "php_easter_egg_vuln_ports": [80,443],
        "php_easter_eggs": ['?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000',
                            '?=PHPE9568F34-D428-11d2-A769-00AA001ACF42',
                            '?=PHPE9568F35-D428-11d2-A769-00AA001ACF42',
                            '?=PHPE9568F36-D428-11d2-A769-00AA001ACF42',]
    }


def conn(targ, port, timeout_sec, socks_proxy):
    try:
        if socks_proxy is not None:
            socks_version = socks.SOCKS5 if socks_proxy.startswith(
                'socks5://') else socks.SOCKS4
            socks_proxy = socks_proxy.rsplit('://')[1]
            if '@' in socks_proxy:
                socks_username = socks_proxy.rsplit(':')[0]
                socks_password = socks_proxy.rsplit(':')[1].rsplit('@')[0]
                socks.set_default_proxy(socks_version, str(socks_proxy.rsplit('@')[1].rsplit(':')[0]),
                                        int(socks_proxy.rsplit(':')[-1]), username=socks_username,
                                        password=socks_password)
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo
            else:
                socks.set_default_proxy(socks_version, str(socks_proxy.rsplit(':')[0]),
                                        int(socks_proxy.rsplit(':')[1]))
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sys.stdout.flush()
        s.settimeout(timeout_sec)
        s.connect((targ, port))
        return s
    except Exception:
        return None


def php_easter_egg_vuln(target, port, timeout_sec, log_in_file, language, time_sleep,
                   thread_tmp_filename, extra_requirements, socks_proxy, scan_id, scan_cmd):
    try:
        try:
            s = conn(target, port, timeout_sec, socks_proxy)
        except Exception:
            return False
        if not s:
            return False
        else:
            user_agent_list = useragents.useragents()
            global php_easter_egg
            if target_type(target) != "HTTP" and port == 443:
                target = 'https://' + target
            if target_type(target) != "HTTP" and port == 80:
                target = 'http://' + target
            if(not target.endswith("/")):
                req_php_credits_url = target + "/" + extra_requirements["php_easter_eggs"][0]
                req_php_logo_url = target + "/" + extra_requirements["php_easter_eggs"][1]
                req_zend_url = target + "/" + extra_requirements["php_easter_eggs"][2]
                req_php_logo2_url = target + "/" + extra_requirements["php_easter_eggs"][3]
            try:
                user_agent = {'User-agent': random.choice(user_agent_list)}
                req_php_credits = requests.get(req_php_credits_url, timeout=10, headers=user_agent)
                user_agent = {'User-agent': random.choice(user_agent_list)}
                req_php_logo = requests.get(req_php_logo_url, timeout=10, headers=user_agent)
                user_agent = {'User-agent': random.choice(user_agent_list)}
                req_zend = requests.get(req_zend_url, timeout=10, headers=user_agent)
                user_agent = {'User-agent': random.choice(user_agent_list)}
                req_php_logo2 = requests.get(req_php_logo2_url, timeout=10, headers=user_agent)
            except requests.exceptions.RequestException: 
               return False
            if req_php_credits.status_code == 200 and 'PHP Credits'.lower() in req_php_credits.text.lower():
                php_easter_egg = "phpinfo() discosed"
                return True
            elif req_php_logo.status_code == 200 and "GIF89a".lower() in req_php_logo.text.lower():
                php_easter_egg = "Php version disclosed which varies with the logo leaked"
                return True
            elif req_zend.status_code == 200 and "GIF89a".lower() in req_zend.text.lower():
                php_easter_egg = "PHP Zend engine detected"
                return True
            elif req_php_logo2.status_code == 200 and "GIF89a".lower() in req_php_logo2.text.lower():
                php_easter_egg = "PHP easter egg detected"
                return True
            else:
                return False
    except Exception as e:
        print(e)
        return False


def __php_easter_egg_vuln(target, port, timeout_sec, log_in_file, language, time_sleep,
                     thread_tmp_filename, extra_requirements, socks_proxy, scan_id, scan_cmd):
    if php_easter_egg_vuln(target, port, timeout_sec, log_in_file, language, time_sleep,
                      thread_tmp_filename, extra_requirements, socks_proxy, scan_id, scan_cmd):
        info(messages(language, "found").format(target, "PHP easter Egg!", php_easter_egg))
        __log_into_file(thread_tmp_filename, 'w', '0', language)
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'php_easter_eggs_vuln_scan',
                           'DESCRIPTION': messages(language, "found").format(target, "PHP easter Egg!", php_easter_egg), 'TIME': now(),
                           'CATEGORY': "scan",
                           'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
        __log_into_file(log_in_file, 'a', data, language)
        return True
    else:
        return False


def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(target) != 'HTTP':
        # requirements check
        new_extra_requirements = extra_requirements_dict()
        if methods_args is not None:
            for extra_requirement in extra_requirements_dict():
                if extra_requirement in methods_args:
                    new_extra_requirements[extra_requirement] = methods_args[extra_requirement]
        extra_requirements = new_extra_requirements
        if ports is None:
            ports = extra_requirements["php_easter_egg_vuln_ports"]
        if target_type(target) == 'HTTP':
            target = target_to_host(target)
        threads = []
        total_req = len(ports)
        thread_tmp_filename = '{}/tmp/thread_tmp_'.format(load_file_path()) + ''.join(
            random.choice(string.ascii_letters + string.digits) for _ in range(20))
        __log_into_file(thread_tmp_filename, 'w', '1', language)
        trying = 0
        keyboard_interrupt_flag = False
        for port in ports:
            port = int(port)
            t = threading.Thread(target=__php_easter_egg_vuln,
                                 args=(target, int(port), timeout_sec, log_in_file, language, time_sleep,
                                       thread_tmp_filename, extra_requirements, socks_proxy, scan_id, scan_cmd))
            threads.append(t)
            t.start()
            trying += 1
            if verbose_level > 3:
                info(
                    messages(language, "trying_message").format(trying, total_req, num, total, target, port, 'php_easter_egg_vuln_scan'))
            while 1:
                try:
                    if threading.activeCount() >= thread_number:
                        time.sleep(0.01)
                    else:
                        break
                except KeyboardInterrupt:
                    keyboard_interrupt_flag = True
                    break
            if keyboard_interrupt_flag:
                break
        # wait for threads
        kill_switch = 0
        kill_time = int(
            timeout_sec / 0.1) if int(timeout_sec / 0.1) != 0 else 1
        while 1:
            time.sleep(0.1)
            kill_switch += 1
            try:
                if threading.activeCount() == 1:
                    break
            except KeyboardInterrupt:
                break
        thread_write = int(open(thread_tmp_filename).read().rsplit()[0])
        if thread_write == 1 and verbose_level != 0:
            info(messages(language, "not_found"))
            data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': '', 'TYPE': 'php_easter_egg_vuln_scan',
                               'DESCRIPTION': messages(language, "not_found"), 'TIME': now(),
                               'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
            __log_into_file(log_in_file, 'a', data, language)
        os.remove(thread_tmp_filename)

    else:
        print("aman")
        warn(messages(language, "input_target_error").format(
            'php_easter_egg_vuln_scan', target))
