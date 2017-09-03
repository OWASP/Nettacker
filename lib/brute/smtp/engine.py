#!/usr/bin/env python
# -*- coding: utf-8 -*-

import threading
import time
import smtplib
import json
import string
import random
import os
from core.alert import *
from core.targets import target_type


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
                server = smtplib.SMTP(target, int(port), timeout=timeout_sec)
            else:
                server = smtplib.SMTP(target, int(port))
            server.starttls()
            exit = 0
            break
        except:
            exit += 1
            if exit is retries:
                warn(messages(language, 73).format(target, port, user, passwd))
                return 1
        time.sleep(time_sleep)
    flag = 1
    try:
        server.login(user, passwd)
        flag = 0
    except smtplib.SMTPException, err:
        pass
    if flag is 0:
        info(messages(language, 70).format(user, passwd, target, port))
        save = open(log_in_file, 'a')
        save.write(json.dumps({_HOST: target, _USERNAME: user, _PASSWORD: passwd, _PORT: port, _TYPE: 'smtp_brute',
                               _DESCRIPTION: messages(language, 66)}) + '\n')
        save.close()
        thread_write = open(thread_tmp_filename, 'w')
        thread_write.write('0')
        thread_write.close()
    else:
        pass
    try:
        server.quit()
    except:
        pass
    return flag


def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep,
          language, verbose_level, show_version, check_update, proxies, retries):  # Main function
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN':
        threads = []
        max = thread_number
        total_req = len(users) * len(passwds)
        thread_tmp_filename = 'tmp/thread_tmp_' + ''.join(
            random.choice(string.ascii_letters + string.digits) for _ in range(20))
        thread_write = open(thread_tmp_filename, 'w')
        thread_write.write('1')
        thread_write.close()
        for port in ports:
            # test smtp
            trying = 0
            portflag = True
            exit = 0
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
                        error(messages(language, 74).format(target, port, str(num), str(total)))
                        portflag = False
                        break
                time.sleep(time_sleep)

            if portflag is True:
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
        if thread_write is 1:
            _HOST = messages(language, 53)
            _USERNAME = messages(language, 54)
            _PASSWORD = messages(language, 55)
            _PORT = messages(language, 56)
            _TYPE = messages(language, 57)
            _DESCRIPTION = messages(language, 58)
            save = open(log_in_file, 'a')
            save.write(json.dumps({_HOST: target, _USERNAME: '', _PASSWORD: '', _PORT: '', _TYPE: 'smtp_brute',
                                   _DESCRIPTION: messages(language, 95)}) + '\n')
            save.close()
        os.remove(thread_tmp_filename)
    else:
        warn(messages(language, 69).format(target))
