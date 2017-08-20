#!/usr/bin/env python
# -*- coding: utf-8 -*-

import threading
import time
import json
from core.alert import *
from core.targets import target_type


def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep,
          language, verbose_level, show_version, check_update, proxies, retries):  # Main function
    if target_type(target) == 'HTTP':  # update later
        threads = []
        max = thread_number
        total_req = len(users) * len(passwds)
        while 1:
            try:
                if timeout_sec is not None:
                    pass
                else:
                    pass
                exit = 0
                break
            except:
                exit += 1
                if exit is retries:
                    error('error')
                    portflag = False
                    break
                time.sleep(0.1)

            if True is True:
                pass

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
        warn(messages(language, 75).format('http_brute', target))
