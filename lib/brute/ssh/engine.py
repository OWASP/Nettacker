#!/usr/bin/env python
# -*- coding: utf-8 -*-

import threading
import time
import json
import paramiko
from core.alert import *
from core.targets import target_type


def login(user, passwd, target, port, timeout_sec, log_in_file, language):
    _HOST = messages(language, 53)
    _USERNAME = messages(language, 54)
    _PASSWORD = messages(language, 55)
    _PORT = messages(language, 56)
    _TYPE = messages(language, 57)
    _DESCRIPTION = messages(language, 58)
    exit = 0
    flag = 1
    while 1:
        try:
            paramiko.Transport((target, int(port)))
            flag = 0
            exit = 0
            break
        except:
            exit += 1
            if exit is 10:
                warn(messages(language, 76).format(target, str(port), user, passwd))
                return 1
            time.sleep(0.1)
    if flag is 0:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if timeout_sec is not None:
                ssh.connect(hostname=target, username=user, password=passwd, port=int(port), timeout=timeout_sec)
            else:
                ssh.connect(hostname=target, username=user, password=passwd, port=int(port))
            info(messages(language, 70).format(user, passwd, target, port))
            save = open(log_in_file, 'a')
            save.write(
                json.dumps({_HOST: target, _USERNAME: user, _PASSWORD: passwd, _PORT: port, _TYPE: 'ssh_brute',
                            _DESCRIPTION: messages(language, 66)}) + '\n')
            save.close()
        except:
            pass
    else:
        pass
    return flag


def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep,
          language, verbose_level, show_version, check_update, proxies, retries):  # Main function
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN':
        threads = []
        max = thread_number
        total_req = len(users) * len(passwds)
        for port in ports:
            # test ssh
            trying = 0
            portflag = True
            exit = 0
            while 1:
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    if timeout_sec is not None:
                        ssh.connect(target, username='', password='', timeout=timeout_sec)
                    else:
                        ssh.connect(target, username='', password='')
                    exit = 0
                    break
                except paramiko.ssh_exception.AuthenticationException, ssherr:
                    if 'Authentication failed.' in ssherr:
                        break
                    else:
                        exit += 1
                        if exit is 3:
                            error(messages(language, 77).format(target, port, str(num), str(total)))
                            portflag = False
                            break
                        time.sleep(0.1)
                except:
                    exit += 1
                    if exit is 3:
                        error(messages(language, 77).format(target, port, str(num), str(total)))
                        portflag = False
                        break
                    time.sleep(0.1)

            if portflag is True:
                for user in users:
                    for passwd in passwds:
                        t = threading.Thread(target=login,
                                             args=(user, passwd, target, port, timeout_sec, log_in_file, language))
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
    else:
        warn(messages(language, 69).format('ssh_brute', target))
