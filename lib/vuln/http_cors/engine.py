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
from urlparse import urlparse, parse_qs
import tldextract
import time


def extra_requirements_dict():
    return {
        "http_cors_vuln_ports": [80, 443]
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


def http_cors(target, port, timeout_sec, log_in_file, language, time_sleep,
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
            urlparsed = urlparse(target)
            scheme = urlparsed.scheme
            domainName =  tldextract.extract(target)
            root = domainName.domain + domainName.suffix
            origin = {
                'wildcard value': '*', 
                'origin reflected': scheme + 'example.com',
                'post-domain wildcard': root + '.example.com',
                'pre-domain wildcard': 'example.com.' + root,
                'null-origin': 'null',
                'broken parser': '%60.example.com',
                'unescaped regex': root.replace('.', 'x', 1),
                'http-origin allowed': 'https://' + urlparsed.netloc,
            }
            time.sleep(0.01)
            headers = {'Referer': 'http://example.foo/CORSexample1.html', 'Origin': origin["wildcard value"],
                       'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:24.0) Gecko/20100101 Firefox/24.0'}
            req = requests.head(target, timeout=10, headers=headers)
            if req.headers['Access-Control-Allow-Origin'] == "*":
                print("Wildcard value CORS misconfiguration found")
                return True
            time.sleep(0.01)
            headers = {'Referer': 'http://example.foo/CORSexample1.html', 'Origin': origin["origin reflected"],
                       'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:24.0) Gecko/20100101 Firefox/24.0'}
            req = requests.head(target, timeout=10, headers=headers)
            if req.headers['Access-Control-Allow-Origin'] == origin["origin reflected"]:
                print("Origin reflected CORS misconfiguration found")
                return True
            time.sleep(0.01)
            headers = {'Referer': 'http://example.foo/CORSexample1.html', 'Origin': origin["post-domain wildcard"],
                       'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:24.0) Gecko/20100101 Firefox/24.0'}
            req = requests.head(target, timeout=10, headers=headers)
            if req.headers['Access-Control-Allow-Origin'] == origin["post-domain wildcard"]:
                print("post-domain wildcard CORS misconfiguration found")
                return True
            time.sleep(0.01)
            headers = {'Referer': 'http://example.foo/CORSexample1.html', 'Origin': origin["pre-domain wildcard"],
                       'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:24.0) Gecko/20100101 Firefox/24.0'}
            req = requests.head(target, timeout=10, headers=headers)
            if req.headers['Access-Control-Allow-Origin'] == origin["pre-domain wildcard"]:
                print("pre-domain wildcard CORS misconfiguration found")
                return True
            time.sleep(0.01)
            headers = {'Referer': 'http://example.foo/CORSexample1.html', 'Origin': origin["null-origin"],
                       'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:24.0) Gecko/20100101 Firefox/24.0'}
            req = requests.head(target, timeout=10, headers=headers)
            if req.headers['Access-Control-Allow-Origin'] == origin["null-origin"]:
                print("null-origin CORS misconfiguration found")
                return True
            time.sleep(0.01)
            headers = {'Referer': 'http://example.foo/CORSexample1.html', 'Origin': origin["broken parser"],
                       'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:24.0) Gecko/20100101 Firefox/24.0'}
            req = requests.head(target, timeout=10, headers=headers)
            if '`.example.com' in req.headers['Access-Control-Allow-Origin']:
                print("broken parser misconfiguration found")
                return True
            time.sleep(0.01)
            headers = {'Referer': 'http://example.foo/CORSexample1.html', 'Origin': origin["unescaped regex"],
                       'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:24.0) Gecko/20100101 Firefox/24.0'}
            req = requests.head(target, timeout=10, headers=headers)
            if req.headers['Access-Control-Allow-Origin'] == origin["unescaped regex"]:
                print("unescaped regex CORS misconfiguration found")
                return True
            time.sleep(0.01)
            headers = {'Referer': 'http://example.foo/CORSexample1.html', 'Origin': origin["http-origin allowed"],
                       'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:24.0) Gecko/20100101 Firefox/24.0'}
            req = requests.head(target, timeout=10, headers=headers)
            if req.headers['Access-Control-Allow-Origin'].startswith("https://"):
                print("http-origin allowed CORS misconfiguration found")
                return True
            else:
                return False

    except Exception as e:
        # some error warning
        return False


def __http_cors(target, port, timeout_sec, log_in_file, language, time_sleep,
                thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    if http_cors(target, port, timeout_sec, log_in_file, language, time_sleep,
                 thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
        info(messages(language, "target_vulnerable").format(target, port,
                                                            'Cross Origin Resource Sharing https://www.owasp.org/index.php/Test_Cross_Origin_Resource_Sharing_(OTG-CLIENT-007)'))
        __log_into_file(thread_tmp_filename, 'w', '0', language)
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'http_cors_vuln',
                           'DESCRIPTION': messages(language, "vulnerable").format('Cross Origin Resource Sharing https://www.owasp.org/index.php/Test_Cross_Origin_Resource_Sharing_(OTG-CLIENT-007)'), 'TIME': now(),
                           'CATEGORY': "vuln",
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
            ports = extra_requirements["http_cors_vuln_ports"]
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
            t = threading.Thread(target=__http_cors,
                                 args=(target, int(port), timeout_sec, log_in_file, language, time_sleep,
                                       thread_tmp_filename, socks_proxy, scan_id, scan_cmd))
            threads.append(t)
            t.start()
            trying += 1
            if verbose_level > 3:
                info(
                    messages(language, "trying_message").format(trying, total_req, num, total, target, port, 'http_cors_vuln'))
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
        kill_switch = -5
        kill_time = int(
            timeout_sec / 0.1222) if int(timeout_sec / 0.1222) is not 0 else 1
        while 1:
            time.sleep(1)
            kill_switch += 1
            try:
                if threading.activeCount() is 1 or kill_switch is kill_time:
                    break
            except KeyboardInterrupt:
                break
        thread_write = int(open(thread_tmp_filename).read().rsplit()[0])
        if thread_write is 1 and verbose_level is not 0:
            info(messages(language, "no_vulnerability_found").format(
                'Cross Origin Resource Sharing'))
            data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': '', 'TYPE': 'http_cors_vuln',
                               'DESCRIPTION': messages(language, "no_vulnerability_found").format('Cross Origin Resource Sharing'), 'TIME': now(),
                               'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
            __log_into_file(log_in_file, 'a', data, language)
        os.remove(thread_tmp_filename)

    else:
        warn(messages(language, "input_target_error").format(
            'http_cors_vuln', target))
