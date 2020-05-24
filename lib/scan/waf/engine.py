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


def extra_requirements_dict():
    return {
        "waf_scan_ports": [80, 443],
        "waf_scan_use_cloudflare": ["True"],
        "waf_scan_use_airlock": ["True"],
        "waf_scan_use_awselb": ["True"],
        #ToDO
        #360
        #barracude
        #incapsula
        #netcontinnum
        #f5asm
        #f5trafficshield
        #hyperguard
        #dotfender
        #profense
        #teros
        #binarysec
        #aeSecure
        #Approach
        #Armor Defense 
        #ArvanCloud
        #ASP.NET Generic 
        #BIG-IP ASM 
        #Cloudfront
        #Deny-All 
        #KeyCDN
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


def waf(target, port, timeout_sec, log_in_file, language, time_sleep,
              thread_tmp_filename, extra_requirements, socks_proxy, scan_id, scan_cmd):
    try:
        s = conn(target, port, timeout_sec, socks_proxy)
        if not s:
            return False
        else:
            if target_type(target) != "HTTP" and port == 443:
                target = 'https://' + target
            if target_type(target) != "HTTP" and port == 80:
                target = 'http://' + target
            global waf
            try:
                time.sleep(0.01)
                req = requests.get(target, timeout=10)
                if re.match('^(cloudflare|__cfduid)=', req.headers['set-cookie']) and extra_requirements["waf_scan_use_cloudflare"][0]:
                    waf = "Cloudflare Detected!!"
                    return True
                time.sleep(0.01)
                req = requests.get(target, timeout=10)
                if re.match('^AL[_-](SESS|LB)(-S)?=', req.headers['set-cookie'], re.IGNORECASE) and extra_requirements["waf_scan_use_airlock"][0]:
                    waf = "AirLock Detected!!"
                    return True
                time.sleep(0.01)
                req = requests.get(target, timeout=10)
                if re.match('.*AWSALB=.*', req.headers['set-cookie'], re.IGNORECASE) and extra_requirements["waf_scan_use_awselb"][0]:
                    waf = "AWS ELB Detected!!"
                    return True
                for i in req.headers:
                    if 'x-amz' in i.lower():
                        waf = "AWS ELB Detected!!"
                        return True
            except:
                return False    
    except Exception:
        # some error warning
        return False


def __waf(target, port, timeout_sec, log_in_file, language, time_sleep,
                thread_tmp_filename, extra_requirements, socks_proxy, scan_id, scan_cmd):
    if waf(target, port, timeout_sec, log_in_file, language, time_sleep,
                 thread_tmp_filename, extra_requirements, socks_proxy, scan_id, scan_cmd):
        info(messages(language, "found").format(target, "Waf ", waf))
        __log_into_file(thread_tmp_filename, 'w', '0', language)
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'waf_scan',
                           'DESCRIPTION': messages(language, "found").format(target, "Waf ", waf), 'TIME': now(),
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
                    new_extra_requirements[
                        extra_requirement] = methods_args[extra_requirement]
        extra_requirements = new_extra_requirements
        if ports is None:
            ports = extra_requirements["waf_scan_ports"]
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
            t = threading.Thread(target=__waf,
                                 args=(target, int(port), timeout_sec, log_in_file, language, time_sleep,
                                       thread_tmp_filename, extra_requirements, socks_proxy, scan_id, scan_cmd))
            threads.append(t)
            t.start()
            trying += 1
            if verbose_level > 3:
                info(
                    messages(language, "trying_message").format(trying, total_req, num, total, target, port, 'waf_scan'))
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
        thread_write = int(open(thread_tmp_filename).read().rsplit()[0])
        if thread_write is 1 and verbose_level is not 0:
            info(messages(language, "not_found"))
            data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': '', 'TYPE': 'waf_scan',
                               'DESCRIPTION': messages(language, "not_found"), 'TIME': now(),
                               'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
            __log_into_file(log_in_file, 'a', data, language)
        os.remove(thread_tmp_filename)

    else:
        warn(messages(language, "input_target_error").format(
            'waf_scan', target))
