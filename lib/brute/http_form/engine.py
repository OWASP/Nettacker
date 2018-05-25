#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import threading
import time
import socks
import socket
import json
import string
import random
if int(sys.version_info[0]) is 3:
    from html.parser import HTMLParser
    import http.cookiejar as cookiejar
else:
    from HTMLParser import HTMLParser
    import cookielib as cookiejar
import urllib
import urllib2
import os
import requests
from core.alert import *
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.log import __log_into_file


def extra_requirements_dict():
    return {
        "http_form_brute_users": ["admin", "root", "test", "ftp", "anonymous", "user", "support", "1"],
        "http_form_brute_passwds": ["admin", "root", "test", "ftp", "anonymous", "user", "1", "12345",
                                    "123456", "124567", "12345678", "123456789", "1234567890", "admin1",
                                    "password!@#", "support", "1qaz2wsx", "qweasd", "qwerty", "!QAZ2wsx",
                                    "password1", "1qazxcvbnm", "zxcvbnm", "iloveyou", "password", "p@ssw0rd",
                                    "admin123", ""],
        "http_form_brute_ports": ["80"],

    }


def login(user, passwd, target, port, timeout_sec, log_in_file, language, retries, time_sleep, thread_tmp_filename,
          socks_proxy, scan_id, scan_cmd):
    username_field = "username"
    password_field = "password"
    exit = 0

    class BruteParser(HTMLParser):

        def __init__(self):
            HTMLParser.__init__(self)
            self.parsed_results = {}

        def handle_starttag(self, tag, attrs):
            if tag == "input":
                for name, value in attrs:
                    if name == "name" and value == username_field:
                        self.parsed_results[username_field] = username_field
                    if name == "name" and value == password_field:
                        self.parsed_results[password_field] = password_field

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
        target_host = str(target) + ":" + str(port)
        flag = 1
        try:
            cookiejar = cookiejar.FileCookieJar("cookies")
            opener = urllib2.build_opener(
                urllib2.HTTPCookieProcessor(cookiejar))
            response = opener.open(target)
            page = response.read()
            parsed_html = BruteParser()
            parsed_html.feed(page)
            parsed_html.parsed_results[username_field] = user
            parsed_html.parsed_results[password_field] = passwd
            post_data = urllib.urlencode(parsed_html.parsed_results).encode()
        except:
            exit += 1
            if exit is retries:
                warn(messages(language, "http_form_auth_failed").format(
                    target, user, passwd, port))
                return 1
            else:
                time.sleep(time_sleep)
                continue
        try:
            if timeout_sec is not None:
                brute_force_response = opener.open(
                    target_host, data=post_data, timeout=timeout_sec)
            else:
                brute_force_response = opener.open(target_host, data=post_data)
            if brute_force_response.code == 200:
                flag = 0
                if flag is 0:
                    info(messages(language, "http_form_auth_success").format(
                        user, passwd, target, port))
                    data = json.dumps(
                        {'HOST': target, 'USERNAME': user, 'PASSWORD': passwd, 'PORT': port, 'TYPE': 'http_form_brute',
                         'DESCRIPTION': messages(language, "login_successful"), 'TIME': now(), 'CATEGORY': "brute",
                         'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}) + "\n"
                    __log_into_file(log_in_file, 'a', data, language)
                    __log_into_file(thread_tmp_filename, 'w', '0', language)
            return flag
        except:
            exit += 1
            if exit is retries:
                warn(messages(language, "http_form_auth_failed").format(
                    target, user, passwd, port))
                return 1
            else:
                time.sleep(time_sleep)
                continue


def check_auth(target, timeout_sec, language, port):
    try:
        if timeout_sec is not None:
            req = requests.get((str(target) + str(port)), timeout = timeout_sec)
        else:
            req = requests.get(str(target) + str(port))
        if req.status_code == 200:
            info(messages(language, "no_auth").format(target, port))
            return 1
        else:
            return 0
    except:
        warn(messages(language, 'no_response'))
        return 1


def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep,
          language, verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(target) != 'HTTP':
        new_extra_requirements = extra_requirements_dict()
        if methods_args is not None:
            for extra_requirement in extra_requirements_dict():
                if extra_requirement in methods_args:
                    new_extra_requirements[
                        extra_requirement] = methods_args[extra_requirement]
        extra_requirements = new_extra_requirements
        if users is None:
            users = extra_requirements["http_form_brute_users"]
        if passwds is None:
            passwds = extra_requirements["http_form_brute_passwds"]
        if ports is None:
            ports = extra_requirements["http_form_brute_ports"]
        if target.lower().startswith('http://') or target.lower().startswith('https://'):
            pass
        else:
            target = 'http://' + str(target)
        threads = []
        total_req = len(users) * len(passwds)
        thread_tmp_filename = '{}/tmp/thread_tmp_'.format(load_file_path()) + ''.join(
            random.choice(string.ascii_letters + string.digits) for _ in range(20))
        __log_into_file(thread_tmp_filename, 'w', '1', language)
        trying = 0
        keyboard_interrupt_flag = False
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
                                                                         target, port, 'http_form_brute'))
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
                timeout_sec / 0.1) if int(timeout_sec / 0.1) is not 0 else 1
            while 1:
                time.sleep(0.1)
                kill_switch += 1
                try:
                    if threading.activeCount() is 1 or kill_switch is kill_time:
                        break
                except KeyboardInterrupt:
                    break
                thread_write = int(
                    open(thread_tmp_filename).read().rsplit()[0])
                if thread_write is 1 and verbose_level is not 0:
                    data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': '',
                                       'TYPE': 'http_form_brute', 'DESCRIPTION': messages(language, "no_user_passwords"), 'TIME': now(),
                                       'CATEGORY': "brute", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}) + "\n"
                    __log_into_file(log_in_file, 'a', data, language)
        os.remove(thread_tmp_filename)
    else:
        warn(messages(language, "input_target_error").format(
            'http_form_brute', target))
