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
import os
from core.alert import *
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.log import __log_into_file
from bs4 import BeautifulSoup
from lib.payload.wordlists import useragents
import requests


def extra_requirements_dict():
    return {
        "csp_vuln_ports": [443, 80],
        "csp_vuln_check_source": ["False"],
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


def content_policy(target, port, timeout_sec, log_in_file, language, time_sleep,
                   thread_tmp_filename, socks_proxy, scan_id, scan_cmd, check_source_flag):
    try:
        s = conn(target, port, timeout_sec, socks_proxy)
        global weak
        weak = False
        if not s:
            return False
        else:
            if target_type(target) != "HTTP" and port == 443:
                target = 'https://' + target
            if target_type(target) != "HTTP" and port == 80:
                target = 'http://' + target

            headers = {'User-agent': random.choice(useragents.useragents())}

            req = requests.get(target, headers=headers,
                               timeout=timeout_sec, verify=False)
            try:
                weak = False
                csp = req.headers['Content-Security-Policy']
                if 'unsafe-inline' in csp or 'unsafe-eval' in csp:
                    weak = True
                return False
            except Exception as e:
                if check_source_flag:
                    soup = BeautifulSoup(req.text, "html.parser")
                    meta_tags = soup.find_all('meta', {'http-equiv': 'Content-Security-Policy'})

                    if len(meta_tags) == 0:
                        return True
                    directives = meta_tags[0].attrs['content']

                    if 'unsafe-inline' in directives or 'unsafe-eval' in directives:
                        weak = True

                    return False
                else:
                    return True
    except Exception as e:
        # some error warning
        return False


def __content_policy(target, port, timeout_sec, log_in_file, language, time_sleep,
                     thread_tmp_filename, socks_proxy, scan_id, scan_cmd, check_source_flag):
    if content_policy(target, port, timeout_sec, log_in_file, language, time_sleep,
                      thread_tmp_filename, socks_proxy, scan_id, scan_cmd, check_source_flag):
        description = ('CSP makes it possible for server administrators to reduce or'
                       ' eliminate the vectors by which XSS can occur by specifying '
                       'the domains that the browser should consider to be valid '
                       'sources of executable scripts. ')
        info(messages(language, "target_vulnerable").format(target, port, description))
        __log_into_file(thread_tmp_filename, 'w', '0', language)
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': port,
                           'TYPE': 'content_security_policy_vuln',
                           'DESCRIPTION': messages(language, "vulnerable").format(description), 'TIME': now(),
                           'CATEGORY': "vuln",
                           'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
        __log_into_file(log_in_file, 'a', data, language)
        return True
    else:
        if not weak:
            return False
        else:
            description = 'weak CSP implementation. Using unsafe-inline or unsafe-eval in CSP is not safe.'
            info(messages(language, "target_vulnerable").format(target, port, description))
            __log_into_file(thread_tmp_filename, 'w', '0', language)
            data = json.dumps(
                {'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'content_security_policy_vuln',
                 'DESCRIPTION': messages(language, "vulnerable").format(description),
                 'TIME': now(),
                 'CATEGORY': "vuln",
                 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
            __log_into_file(log_in_file, 'a', data, language)
            return True


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
            ports = extra_requirements["csp_vuln_ports"]
        check_source_flag = False
        if extra_requirements["csp_vuln_check_source"][0] == "True":
            check_source_flag = True
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
            t = threading.Thread(target=__content_policy,
                                 args=(target, int(port), timeout_sec, log_in_file, language, time_sleep,
                                       thread_tmp_filename, socks_proxy, scan_id, scan_cmd, check_source_flag))
            threads.append(t)
            t.start()
            trying += 1
            if verbose_level > 3:
                info(
                    messages(language, "trying_message").format(trying, total_req, num,
                                                                total, target, port, 'content_security_policy_vuln'))
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
                if threading.activeCount() == 1 or kill_switch == kill_time:
                    break
            except KeyboardInterrupt:
                break
        thread_write = int(open(thread_tmp_filename).read().rsplit()[0])
        if thread_write == 1 and verbose_level != 0:
            info(messages(language, "no_vulnerability_found").format(
                'Content Security Policy'))
            data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': '',
                               'TYPE': 'content_security_policy_vuln',
                               'DESCRIPTION': messages(language, "no_vulnerability_found").format(
                                   'Content Security Policy'),
                               'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
            __log_into_file(log_in_file, 'a', data, language)
        os.remove(thread_tmp_filename)

    else:
        warn(messages(language, "input_target_error").format(
            'content_security_policy_vuln', target))
