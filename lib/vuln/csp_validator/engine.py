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
from termcolor import colored


def extra_requirements_dict():
    return {
        "csp_validator_ports": [443],
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
    except Exception as e:
        return None


def csp_validator(target, port, timeout_sec, log_in_file, language, time_sleep,
              thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    try:
        s = conn(target, port, timeout_sec, socks_proxy)
        if not s:
            return False
        else:
            if target_type(target) != "HTTP" and port == 443:
                target = 'https://' + target
            if target_type(target) != "HTTP" and port == 80:
                target = 'http://' + target
            
            req = requests.get(target)
            subs = []
            if req.status_code is 200:
                result = req.headers["content-security-policy"]
                result = result.split(";")
                for i in result:
                    if("." in i):
                        new = i.split(" ")
                        finalString = []
                        for j in new:
                            if("." in j):
                                finalString.append(j)
                        newString = new[1] + ': ' + '\t\t\n'.join(finalString)
                        subs.append(newString)
                return subs
            else:
                return []

    except Exception as e:
        # some error warning
        return []


def __csp_validator(target, port, timeout_sec, log_in_file, language, time_sleep,
              thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    
    if csp_validator(target, port, timeout_sec, log_in_file, language, time_sleep,
                      thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
        # info(messages(language, "target_vulnerable").format(target, port,
                                                            # 'CSP makes it possible for server administrators to reduce or eliminate the vectors by which XSS can occur by specifying the domains that the browser should consider to be valid sources of executable scripts. '))
        __log_into_file(thread_tmp_filename, 'w', '0', language)
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'content_security_policy_vuln',
                           'DESCRIPTION': messages(language, "vulnerable").format('CSP makes it possible for server administrators to reduce or eliminate the vectors by which XSS can occur by specifying the domains that the browser should consider to be valid sources of executable scripts. '), 'TIME': now(),
                           'CATEGORY': "vuln",
                           'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
        # __log_into_file(log_in_file, 'a', data, language)

        return csp_validator(target, port, timeout_sec, log_in_file, language, time_sleep,
              thread_tmp_filename, socks_proxy, scan_id, scan_cmd)
    else:
        return []

def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(target) != 'HTTP':
        # requirements check
        new_extra_requirements = extra_requirements_dict()
        if methods_args is not None:
            for extra_requirement in extra_requirements_dict():
                if extra_requirement in methods_args:
                    new_extra_requirements[
                        extra_requirement] = methods_args[extra_requirement]
        extra_requirements = new_extra_requirements
        if ports is None:
            ports = extra_requirements["csp_validator_ports"]
        if target_type(target) == 'HTTP':
            target = target_to_host(target)
        threads = []
        total_req = len(ports)
        # print(total_req)
        thread_tmp_filename = '{}/tmp/thread_tmp_'.format(load_file_path()) + ''.join(
            random.choice(string.ascii_letters + string.digits) for _ in range(20))
        __log_into_file(thread_tmp_filename, 'w', '1', language)
        trying = 0
        keyboard_interrupt_flag = False
        for port in ports:
            port = int(port)
            t = threading.Thread(target=__csp_validator,
                                 args=(target, port, timeout_sec, log_in_file, language, time_sleep,
              thread_tmp_filename, socks_proxy, scan_id, scan_cmd))
            threads.append(t)
            t.start()
            trying += 1
            if verbose_level > 3:
                info(
                    messages(language, "trying_message").format(trying, total_req, num, total, target, port, 'csp_validator_vuln'))
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
            timeout_sec / 0.1) if int(timeout_sec / 0.1) is not 0 else 1
        while 1:
            time.sleep(0.1)
            kill_switch += 1
            try:
                if threading.activeCount() is 1 or kill_switch is kill_time:
                    break
            except KeyboardInterrupt:
                break
        subs = __csp_validator(target, port, timeout_sec, log_in_file, language, time_sleep,
              thread_tmp_filename, socks_proxy, scan_id, scan_cmd)
        if len(subs) is not 0:
            info(messages(language, "len_subdomain_found").format(len(subs)))
            for sub in subs:
               
                data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': '', 'TYPE': 'CSP domains found!!',
                                   'DESCRIPTION': sub, 'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id,
                                   'SCAN_CMD': scan_cmd}) + "\n"
                __log_into_file(log_in_file, 'a', data, language)
        return subs

    else:
        warn(messages(language, "input_target_error").format(
            'csp_validator_vuln', target))
        return []