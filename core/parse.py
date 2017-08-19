#!/usr/bin/env python
# -*- coding: utf-8 -*-

import threading
import time
import os
import datetime
import random
import string
from core.targets import analysis
from core.attack import start_attack
from core.alert import info
from core.alert import warn
from core.alert import error
from core.alert import write
from core.alert import messages
from core.log import sort_logs
from core.load_modules import load_all_modules
from core.args_loader import load_all_args
from core.args_loader import check_all_required


def load():
    write('\n\n')

    # load all modules in lib/brute and lib/scan
    module_names = load_all_modules()

    # Parse ARGVs
    parser, (options, args) = load_all_args(module_names)

    # Filling Options
    check_ranges = options.check_ranges
    check_subdomains = options.check_subdomains
    targets = options.targets
    targets_list = options.targets_list
    thread_number = options.thread_number
    thread_number_host = options.thread_number_host
    log_in_file = options.log_in_file
    scan_method = options.scan_method
    exclude_method = options.exclude_method
    users = options.users
    users_list = options.users_list
    passwds = options.passwds
    passwds_list = options.passwds_list
    timeout_sec = options.timeout_sec
    ports = options.ports
    time_sleep = options.time_sleep
    language = options.language
    verbose_level = options.verbose_level
    show_version = options.show_version
    check_update = options.check_update
    proxies = options.proxies
    retries = options.retries

    info(messages("en", 0))
    # Checking Requirements
    (targets, targets_list, thread_number, thread_number_host,
     log_in_file, scan_method, exclude_method, users, users_list,
     passwds, passwds_list, timeout_sec, ports, parser, module_names, language, verbose_level, show_version,
     check_update, proxies, retries) = \
        check_all_required(
            targets, targets_list, thread_number, thread_number_host,
            log_in_file, scan_method, exclude_method, users, users_list,
            passwds, passwds_list, timeout_sec, ports, parser, module_names, language, verbose_level, show_version,
            check_update, proxies, retries
        )

    suff = str(datetime.datetime.now()).replace(' ', '_').replace(':', '-') + '_' + ''.join(
        random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
    subs_temp = 'tmp/subs_temp_%s' % (suff)
    range_temp = 'tmp/ranges_%s' % (suff)
    total_targets = -1
    for total_targets, _ in enumerate(
            analysis(targets, check_ranges, check_subdomains, subs_temp, range_temp, log_in_file, time_sleep,
                     language)):
        pass
    total_targets += 1
    total_targets = total_targets * len(scan_method)
    targets = analysis(targets, check_ranges, check_subdomains, subs_temp, range_temp, log_in_file, time_sleep,
                       language)
    threads = []
    trying = 0
    for target in targets:
        for sm in scan_method:
            trying += 1
            t = threading.Thread(target=start_attack, args=(
                str(target).rsplit()[0], trying, total_targets, sm, users, passwds, timeout_sec, thread_number,
                ports, log_in_file, time_sleep, language))
            threads.append(t)
            t.start()
            while 1:
                n = 0
                for thread in threads:
                    if thread.isAlive() is True:
                        n += 1
                    else:
                        threads.remove(thread)
                if n >= thread_number_host:
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
    info(messages(language, 42))
    os.remove(subs_temp)
    os.remove(range_temp)
    info(messages(language, 43))
    sort_logs(log_in_file)
    write('\n')
    info(messages(language, 44))
    write('\n\n')
