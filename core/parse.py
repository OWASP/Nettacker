#!/usr/bin/env python
# -*- coding: utf-8 -*-

import threading
import time
import os
import datetime
import random
import string
import sys
from core.targets import analysis
from core.attack import start_attack
from core.alert import info
from core.alert import warn
from core.alert import error
from core.alert import write
from core.alert import messages
from core.log import sort_logs
from core.load_modules import load_all_modules
from core.load_modules import load_all_graphs
from core.args_loader import load_all_args
from core.args_loader import check_all_required
from core.update import _check
from core.compatible import _version_info


def load():
    write('\n\n')

    # load all modules in lib/brute, lib/scan, lib/graph
    module_names = load_all_modules()
    graph_names = load_all_graphs()

    # Parse ARGVs
    try:
        parser, options = load_all_args(module_names, graph_names)
    except SystemExit:
        from core.color import finish
        finish()
        sys.exit(1)
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
    proxies_file = options.proxies_file
    retries = options.retries
    graph_flag = options.graph_flag
    help_menu_flag = options.help_menu_flag
    ping_flag = options.ping_flag
    methods_args = options.methods_args

    info(messages(language, 0))
    # Checking Requirements
    (targets, targets_list, thread_number, thread_number_host,
     log_in_file, scan_method, exclude_method, users, users_list,
     passwds, passwds_list, timeout_sec, ports, parser, module_names, language, verbose_level, show_version,
     check_update, proxies, proxies_file, retries, graph_flag, help_menu_flag, methods_args) = \
        check_all_required(
            targets, targets_list, thread_number, thread_number_host,
            log_in_file, scan_method, exclude_method, users, users_list,
            passwds, passwds_list, timeout_sec, ports, parser, module_names, language, verbose_level, show_version,
            check_update, proxies, proxies_file, retries, graph_flag, help_menu_flag, methods_args
        )
    # check for update
    __version__, __code_name__ = _version_info()
    _check(__version__, __code_name__, language)

    info(messages(language, 96).format(len(graph_names) + len(module_names) - 1))
    suff = str(datetime.datetime.now()).replace(' ', '_').replace(':', '-') + '_' + ''.join(
        random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
    subs_temp = 'tmp/subs_temp_%s' % (suff)
    range_temp = 'tmp/ranges_%s' % (suff)
    total_targets = -1
    for total_targets, _ in enumerate(
            analysis(targets, check_ranges, check_subdomains, subs_temp, range_temp, log_in_file, time_sleep,
                     language, verbose_level, show_version, check_update, proxies, retries)):
        pass
    total_targets += 1
    total_targets = total_targets * len(scan_method)
    targets = analysis(targets, check_ranges, check_subdomains, subs_temp, range_temp, log_in_file, time_sleep,
                       language, verbose_level, show_version, check_update, proxies, retries)
    threads = []
    trying = 0
    for target in targets:
        for sm in scan_method:
            trying += 1
            t = threading.Thread(target=start_attack, args=(
                str(target).rsplit()[0], trying, total_targets, sm, users, passwds, timeout_sec, thread_number,
                ports, log_in_file, time_sleep, language, verbose_level, show_version, check_update, proxies,
                retries, ping_flag, methods_args))
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
    sort_logs(log_in_file, language, graph_flag)
    write('\n')
    info(messages(language, 44))
    write('\n\n')
    from core.color import finish
    finish()
