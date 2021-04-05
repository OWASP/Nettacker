#!/usr/bin/env python
# -*- coding: utf-8 -*-

import threading
import time
import socks
from core.compatible import version
import socket
import json
import string
import random
import base64
import requests
import os
from core.alert import warn, info, messages
import logging
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.log import __log_into_file
from lib.payload.wordlists import usernames, passwords

HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)\
             AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;\
            q=0.9,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
    }
CODES = [401,403]

def extra_requirements_dict():
    return {
        "http_basic_auth_brute_users": usernames.users(),
        "http_basic_auth_brute_passwds": passwords.passwords(),
        "http_basic_auth_brute_ports": ["80", "443"],
    }


def login(user, passwd, target, port, timeout_sec, log_in_file, language, retries, time_sleep, thread_tmp_filename,
          socks_proxy, scan_id, scan_cmd):
    exit = 0
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
            creds = user + ":" + passwd
            HEADERS["Authorization"] = "Basic " + base64.b64encode(creds.encode()).decode()
            req = requests.get(
                target, timeout=timeout_sec, headers=HEADERS, verify=False)
            flag = 1
            if req.status_code in CODES:
                exit += 1
                if exit == retries:
                    warn(messages(language, "http_auth_failed").format(
                        target, user, passwd, port))
                    return 1
                else:
                    time.sleep(time_sleep)
                    continue
            elif req.status_code not in CODES:
                flag = 0
                if flag == 0:
                    info(messages(language, "http_auth_success").format(
                        user, passwd, target, port))
                    data = json.dumps(
                        {'HOST': target, 'USERNAME': user, 'PASSWORD': passwd, 'PORT': port,
                         'TYPE': 'http_basic_auth_brute', 'DESCRIPTION': messages(language, "login_successful"), 'TIME': now(),
                         'CATEGORY': "brute", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}) + "\n"
                    __log_into_file(log_in_file, 'a', data, language)
                    __log_into_file(thread_tmp_filename, 'w', '0', language)
                break
        except Exception:
            # logging.exception("message")
            exit += 1
            if exit == retries:
                warn(messages(language, "http_auth_failed").format(
                    target, user, passwd, port))
                return 1
            else:
                time.sleep(time_sleep)
                continue
        return flag


def check_auth(target, timeout_sec, language, port):
    try:
        req = requests.get(target, timeout=timeout_sec, headers=HEADERS, verify=False)
        if req.status_code not in CODES:
            info(messages(language, "no_auth").format(target, port))
            return 1
        else:
            return 0
    except requests.exceptions.RequestException:
        # logging.exception("message")
        warn(messages(language, 'no_response'))
        return 1


def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep,
          language, verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(target) != 'HTTP':
        new_extra_requirements = extra_requirements_dict()
        if methods_args is not None:
            for extra_requirement in extra_requirements_dict():
                if extra_requirement in methods_args:
                    new_extra_requirements[
                        extra_requirement] = methods_args[extra_requirement]
        extra_requirements = new_extra_requirements
        if users is None:
            users = extra_requirements["http_basic_auth_brute_users"]
        if passwds is None:
            passwds = extra_requirements["http_basic_auth_brute_passwds"]
        if ports is None:
            ports = extra_requirements["http_basic_auth_brute_ports"]
        if target.lower().startswith('http://') or target.lower().startswith('https://'):
            pass
        else:
            try:
                target = 'http://' + str(target)
                requests.get(target, headers=HEADERS, verify=False)
            except Exception:
                try:
                    target = 'https://' + str(target)
                    requests.get(target, headers=HEADERS, verify=False)
                except Exception:
                    pass
        threads = []
        total_req = len(users) * len(passwds)
        thread_tmp_filename = '{}/tmp/thread_tmp_'.format(load_file_path()) + ''.join(
            random.choice(string.ascii_letters + string.digits) for _ in range(20))
        __log_into_file(thread_tmp_filename, 'w', '1', language)
        trying = 0
        keyboard_interrupt_flag = False
        if target.endswith("/"):
            target = target.strip("/")
        for port in ports:
            if check_auth(target, timeout_sec, language, port):
                continue
            for user in users:
                for passwd in passwds:
                    t = threading.Thread(target=login,
                                         args=(
                                             user, passwd, target, port, timeout_sec, log_in_file, language,
                                             retries, time_sleep, thread_tmp_filename, socks_proxy, scan_id, scan_cmd))
                    threads.append(t)
                    t.start()
                    trying += 1
                    if verbose_level > 3:
                        info(messages(language, "trying_message").format(trying, total_req, num, total,
                                                                         target, port, 'http_basic_auth_brute'))
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
                if keyboard_interrupt_flag:
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
                thread_write = int(
                    open(thread_tmp_filename).read().rsplit()[0])
                if thread_write == 1 and verbose_level != 0:
                    data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': '',
                                       'TYPE': 'http_basic_auth_brute', 'DESCRIPTION': messages(language, "no_user_passwords"),
                                       'TIME': now(), 'CATEGORY': "brute", 'SCAN_ID': scan_id,
                                       'SCAN_CMD': scan_cmd}) + "\n"
                    __log_into_file(log_in_file, 'a', data, language)
        os.remove(thread_tmp_filename)
    else:
        warn(messages(language, "input_target_error").format(
            'http_basic_auth_brute', target))
