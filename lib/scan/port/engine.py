#!/usr/bin/env python
import socket
import time
import json
import threading
from core.alert import *
from core.targets import target_type


def connect(host, port,timeout_sec,log_in_file):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if timeout_sec is not None:
            s.settimeout(timeout_sec)
        s.connect((host, port))
        s.close()
        info('server:' + host + ' port:' + str(port) + ' found!')
        save = open(log_in_file,'a')
        save.write(json.dumps({'HOST': host, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'port_scan',
                               'DESCRIPTION': 'OPEN PORT'}) + '\n')
        save.close()
        return True
    except socket.error:
        return False


def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file): # Main function
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN':
        threads = []
        max = thread_number
        trying = 0
        total_req = len(ports)
        for port in ports:
            t = threading.Thread(target=connect, args=(target, int(port),timeout_sec,log_in_file))
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
            info('trying ' + str(trying) + ' of ' + str(total_req) + ' in process ' + str(num) + ' of ' + str(
                total) + ' ' + target + ':' + str(port))

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
        warn('input target for port_scan module must be DOMAIN or SINGLE_IPv4, skipping %s'%str(target))