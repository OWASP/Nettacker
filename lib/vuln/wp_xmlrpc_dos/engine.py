#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author Aman Gupta; github.com/aman566

import socket
import threading
import time
import string
import random
import os
import json
import requests
import socks
from core.alert import messages, info, warn
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.log import __log_into_file
from lib.payload.wordlists.useragents import useragents

def extra_requirements_dict():
    return {
        "wp_xmlrpc_dos_vuln_ports": [80, 443]
    }


def check(target, port, headers, timeout_sec, log_in_file, language, retries, time_sleep, thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    time.sleep(time_sleep)
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
                socks.set_default_proxy(socks_version, str(
                    socks_proxy.rsplit(':')[0]), int(socks_proxy.rsplit(':')[1]))
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo
        _n = 0
        while 1:
            try:
                if target_type(target) != "HTTP" and port == 443:
                    target = 'https://' + target
                if target_type(target) != "HTTP" and port == 80:
                    target = 'http://' + target
                target = target + '/xmlrpc.php'
                postdata = '''<?xml version="1.0" encoding="utf-8"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'''
                _r = requests.post(target, timeout=timeout_sec, verify=False, headers=headers, data=postdata)
                if "demo.sayhello" in _r.text.lower():
                    info(messages(language, "target_vulnerable").format(target, port, "XMLRPC DOS attacks"))
                    __log_into_file(thread_tmp_filename, 'w', '0', language)
                    data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'wp_xmlrpc_dos_vuln', 'DESCRIPTION': messages(language, "vulnerable").format("XML-RPC DOS attacks!!"), 'TIME': now(), 'CATEGORY': "vuln", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}) + "\n"
                    __log_into_file(log_in_file, 'a', data, language)
            except Exception:
                _n += 1
                if _n is retries:
                    warn(messages(language, "http_connection_timeout").format(target))
                    return 1
            return True
    except Exception:
        return False


def test(target, port, headers, socks_proxy):
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
            socks.set_default_proxy(socks_version, str(
                socks_proxy.rsplit(':')[0]), int(socks_proxy.rsplit(':')[1]))
            socket.socket = socks.socksocket
            socket.getaddrinfo = getaddrinfo
    while 1:
        try:
            if target_type(target) != "HTTP" and port == 443:
                target = 'https://' + target
            if target_type(target) != "HTTP" and port == 80:
                target = 'http://' + target
            postdata = '''<?xml version="1.0" encoding="utf-8"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'''
            try:
                if target.endswith("/"):
                    target = target[:-1]
                req = requests.post(target+'/xmlrpc.php', verify=False, data=postdata, headers=headers)
                if 'demo.sayhello' in req.text.lower():
                    return True
                return False
            except Exception:
                return False
        except Exception:
            return False
            


def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(
            target) != 'HTTP' or target_type(target) != 'SINGLE_IPv6':
        # rand useragent
        user_agent_list = useragents()
        headers = {'User-agent': random.choice(user_agent_list), 'Content-Type': 'text/xml'}

        # requirements check
        new_extra_requirements = extra_requirements_dict()
        if methods_args is not None:
            for extra_requirement in extra_requirements_dict():
                if extra_requirement in methods_args:
                    new_extra_requirements[
                        extra_requirement] = methods_args[extra_requirement]
        extra_requirements = new_extra_requirements
        threads = []

        if ports is None:
            ports = extra_requirements["wp_xmlrpc_dos_vuln_ports"]
        if verbose_level > 3:
            total_req = len(ports)
        else:
            total_req = len(ports)
        thread_tmp_filename = '{}/tmp/thread_tmp_'.format(load_file_path()) + ''.join(
            random.choice(string.ascii_letters + string.digits) for _ in range(20))
        __log_into_file(thread_tmp_filename, 'w', '1', language)
        trying = 0
        if target_type(target) != "HTTP":
            target = 'https://' + target
        for port in ports:
            if test(str(target), port, headers, socks_proxy) is True:
                keyboard_interrupt_flag = False
                t = threading.Thread(target=check, args=(target, port, headers, timeout_sec, log_in_file, language, retries, time_sleep, thread_tmp_filename, socks_proxy, scan_id, scan_cmd))
                threads.append(t)
                t.start()
                trying += 1
                if verbose_level > 3:
                    info(messages(language, "trying_message").format(trying, total_req, num, total, target_to_host(target), port, 'wp_xmlrpc_dos_vuln'))
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

            else:
                warn(messages(language, "open_error").format(target))

        # wait for threads

        kill_switch = 0
        kill_time = int(
            timeout_sec / 0.1) if int(timeout_sec / 0.1) != 0 else 1
        while 1:
            time.sleep(0.1)
            kill_switch += 1
            try:
                if threading.activeCount() == 1 or kill_switch == kill_time:
                    break
            except KeyboardInterrupt:
                break
        thread_write = int(open(thread_tmp_filename).read().rsplit()[0])
        if thread_write == 1 and verbose_level != 0:

            info(messages(language, "no_vulnerability_found").format(
                'XML-RPC'))
            data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'wp_xmlrpc_dos_vuln', 'DESCRIPTION': messages(language, "no_vulnerability_found").format("XML-RPC DOS attacks"), 'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}) + "\n"
            __log_into_file(log_in_file, 'a', data, language)
        os.remove(thread_tmp_filename)
    else:
        warn(messages(language, "input_target_error").format(
            'wp_xmlrpc_dos_vuln', target))
