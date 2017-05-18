#!/usr/bin/env python
import socket
import time
import threading
from core.alert import *

def connect(host, port,timeout_sec):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if timeout_sec is not None:
            s.settimeout(timeout_sec)
        s.connect((host, port))
        s.close()
        info('server:' + host + ' port:' + str(port) + ' found!')
        f = open('results.txt','a')
        f.write('open port ---> ' + host + ':' + str(port) + '\n')
        f.close()
        return True
    except socket.error:
        return False

def start(target, ports, timeout_sec, thread_number, num, total): # Main function
    threads = []
    max = thread_number
    trying = 0
    total_req = len(ports)
    for port in ports:
        t = threading.Thread(target=connect, args=(target, int(port),timeout_sec))
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