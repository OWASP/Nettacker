#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import time
import json
import threading
import string
import random
import os
from core.alert import *
from core.targets import target_type


def connect(host, port, timeout_sec, log_in_file, language, time_sleep, thread_tmp_filename):
    _HOST = messages(language, 53)
    _USERNAME = messages(language, 54)
    _PASSWORD = messages(language, 55)
    _PORT = messages(language, 56)
    _TYPE = messages(language, 57)
    _DESCRIPTION = messages(language, 58)
    time.sleep(time_sleep)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if timeout_sec is not None:
            s.settimeout(timeout_sec)
        s.connect((host, port))
        s.close()
        info(messages(language, 80).format(host, port))
        save = open(log_in_file, 'a')
        save.write(json.dumps({_HOST: host, _USERNAME: '', _PASSWORD: '', _PORT: port, _TYPE: 'port_scan',
                               _DESCRIPTION: messages(language, 79)}) + '\n')
        save.close()
        thread_write = open(thread_tmp_filename, 'w')
        thread_write.write('0')
        thread_write.close()
        return True
    except socket.error:
        return False


def start(target, users, passwds, port, timeout_sec, thread_number, num, total, log_in_file, time_sleep,
          language, verbose_level, show_version, check_update, proxies, retries):  # Main function
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN':
        threads = []
        max = thread_number
        trying = 0
        total_req = len(str(port).rsplit())
        thread_tmp_filename = 'tmp/thread_tmp_' + ''.join(
            random.choice(string.ascii_letters + string.digits) for _ in range(20))
        thread_write = open(thread_tmp_filename, 'w')
        thread_write.write('1')
        thread_write.close()

        t = threading.Thread(target=connect,
                             args=(target, int(port), timeout_sec, log_in_file, language, time_sleep,
                                   thread_tmp_filename))
        threads.append(t)
        t.start()
        trying += 1
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
        info(messages(language, 72).format(trying, total_req, num, total, target, port))

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
            save.write(json.dumps({_HOST: target, _USERNAME: '', _PASSWORD: '', _PORT: '', _TYPE: 'port_scan',
                                   _DESCRIPTION: messages(language, 94)}) + '\n')
            save.close()
        os.remove(thread_tmp_filename)

    else:
        warn(messages(language, 69).format('port_scan', target))
