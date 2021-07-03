#!/usr/bin/env python
# -*- coding: utf-8 -*-

from inspect import getargspec
from logging import exception
from lib.socks_resolver.engine import getaddrinfo
from core.alert import warn, info, messages, error
from core.load_modules import load_file_path
from core._time import now
from core.log import __log_into_file
import threading
import string
import time
import json
import os
import random
import socks
import socket

def socks_proxy(func):
    def inner_wrapper(*args, **kwargs):
        flag = False
        socks_proxy_in_args = False
        socks_proxy_in_kwargs = False
        i = 0
        argspec = getargspec(func)
        arg_list = argspec[0]
        if 'socks_proxy' in arg_list:
            flag = True
        if flag == True and len(args) > 0:
            for arg in arg_list:
                if arg != 'socks_proxy':
                    i = i + 1
                else:
                    try:
                        if i<len(args) and args[i] is not None:
                            socks_proxy = args[i]
                            socks_proxy_in_args = True
                    except IndexError as ie:
                        pass
                    break
        if kwargs.get('socks_proxy') is not None:
            socks_proxy = kwargs.get('socks_proxy')
            socks_proxy_in_kwargs = True
        try:
            if socks_proxy is not None and (socks_proxy_in_args or socks_proxy_in_kwargs):
                socks_version = socks.SOCKS5 if socks_proxy.startswith(
                    'socks5://')  else socks.SOCKS4
                socks_proxy = socks_proxy.rsplit('://')[1]
                if '@' in socks_proxy:
                    socks_username = socks_proxy.rsplit(':')[0]
                    socks_password = socks_proxy.rsplit(':')[1].rsplit('@')[0]
                    socks.set_default_proxy(socks_version, str(socks_proxy.rsplit('@')[1].rsplit(':')[0]),
                                            int(socks_proxy.rsplit(':')[-1]), username=socks_username,
                                            password=socks_password)
                    socket.socket = socks.socksocket
                    socket.getaddrinfo = getaddrinfo()
                else:
                    socks.set_default_proxy(socks_version, str(socks_proxy.rsplit(':')[0]),
                                            int(socks_proxy.rsplit(':')[1]))
                    socket.socket = socks.socksocket
                    socket.getaddrinfo = getaddrinfo()
            return func(*args, **kwargs)
        except Exception:
            pass
    return inner_wrapper

def main_function(*args, **kwargs):
    new_extra_requirements = args[0]
    target_name = args[1]
    info_message = args[2]
    no_vuln_found_msg = args[3]
    def start_function(func):
        def inner_wrapper(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language, verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):
            from core.targets import target_type
            from core.targets import target_to_host
            if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(target) != 'HTTP':
                if methods_args is not None:
                    for extra_requirement in new_extra_requirements:
                        if extra_requirement in methods_args:
                            new_extra_requirements[
                                extra_requirement] = methods_args[extra_requirement]
                switch = False
                for i,j in new_extra_requirements.items():
                    if(i.endswith('ports')):
                        new_ports = new_extra_requirements[i]
                        switch = True
                if switch == False:
                    new_ports = [443]
                if ports is None:
                    ports = new_ports
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
                    t = threading.Thread(target=target_name,
                                        args=(target, int(port), timeout_sec, log_in_file, language, time_sleep,
                                            thread_tmp_filename, socks_proxy, scan_id, scan_cmd))
                    threads.append(t)
                    t.start()
                    trying += 1
                    if verbose_level > 3:
                        info(
                            messages(language, "trying_message").format(trying, total_req, num, total, target, port, info_message))
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
                        no_vuln_found_msg))
                    data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': '', 'TYPE': info_message,
                                    'DESCRIPTION': messages(language, "no_vulnerability_found").format(no_vuln_found_msg), 'TIME': now(),
                                    'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
                    __log_into_file(log_in_file, 'a', data, language)
                os.remove(thread_tmp_filename)
                return func(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language, verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd)

            else:
                warn(messages(language, "input_target_error").format(
                    info_message, target))
        return inner_wrapper
    return start_function