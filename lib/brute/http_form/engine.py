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
from six import text_type
from core.compatible import version
import os
import re
import requests
from core.alert import warn, info, messages
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from lib.socks_resolver.engine import getaddrinfo
import mechanize
import logging
from core._time import now
from core.log import __log_into_file
from bs4 import BeautifulSoup
from core.compatible import version
from lib.payload.wordlists import usernames, passwords

if version() == 3:
    from urllib.parse import urlparse
else:
    from urlparse import urlparse
HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)\
             AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;\
            q=0.9,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
    }

def extra_requirements_dict():
    return {
        "http_form_brute_users": usernames.users(),
        "http_form_brute_passwds": passwords.passwords(),
        "http_form_brute_ports": ["80", "443"],
    }

def get_all_forms(url):
    session = requests.Session()
    res = session.get(url)
    soup = BeautifulSoup(res.text, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    details = {}
    action = form.attrs.get("action").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value =input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

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
    try:
        forms = get_all_forms(target)
        for i, form in enumerate(forms, start=1):
            form_details = get_form_details(form)
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] == "hidden":
                    data[input_tag["name"]] = input_tag["value"]
                elif input_tag["type"] == "text":
                    data[input_tag["name"]] = user
                elif input_tag["type"] == "password":
                    data[input_tag["name"]] = passwd
            target_details = urlparse(target)
            scheme = target_details.scheme
            domain = target_details.netloc
            path = target_details.path
            try:
                if form_details["action"].startswith("/"):
                    url = scheme + "://" + domain + form_details["action"]
                else:
                    if target.endswith("/"):
                        url = scheme + "://" + domain + form_details["action"]
                    else:
                        url = scheme + "://" + domain + path + "/" + form_details["action"]
                if form_details["method"] == "post":
                    res = requests.post(url, data=data, verify=False)
                elif form_details["method"] == "get":
                    res = requests.get(url, params=data, verify=False)
                if "login" not in res.text:
                    info(messages(language, "http_form_auth_success").format(
                    user, passwd, target, port))
                    data = json.dumps(
                        {'HOST': target, 'USERNAME': user, 'PASSWORD': passwd, 'PORT': port, 'TYPE': 'http_form_brute',
                        'DESCRIPTION': messages(language, "login_successful"), 'TIME': now(), 'CATEGORY': "brute",
                        'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}) + "\n"
                    __log_into_file(log_in_file, 'a', data, language)
                    __log_into_file(thread_tmp_filename, 'w', '0', language)
                    return
            except Exception:
                # logging.exception("message")
                pass
    except Exception:
        # logging.exception("message")
        exit += 1
        if exit == retries:
            warn(messages(language, "http_form_auth_failed").format(
                target, user, passwd, port))
            return 1
        else:
            time.sleep(time_sleep)
        

def check(target, timeout_sec, language, port):
    try:
        requests.get(target, verify=False, timeout=timeout_sec, headers=HEADERS)
        return True
    except Exception:
        warn(messages(language, 'no_response'))
        return False


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
            if check("http://"+target_to_host(target), timeout_sec, language, port):
                target = target
            elif check("https://"+target_to_host(target), timeout_sec, language, port):
                target = "https" + target[4:]
            
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
            while 1:
                time.sleep(0.1)
                kill_switch += 1
                try:
                    if threading.activeCount() == 1:

                        break
                except KeyboardInterrupt:
                    break
                thread_write = int(
                    open(thread_tmp_filename).read().rsplit()[0])
                if thread_write == 1 and verbose_level != 0:
                    data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': '',
                                       'TYPE': 'http_form_brute', 'DESCRIPTION': messages(language, "no_user_passwords"), 'TIME': now(),
                                       'CATEGORY': "brute", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}) + "\n"
                    __log_into_file(log_in_file, 'a', data, language)
        os.remove(thread_tmp_filename)
    else:
        warn(messages(language, "input_target_error").format(
            'http_form_brute', target))
