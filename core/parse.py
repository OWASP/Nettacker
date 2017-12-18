#!/usr/bin/env python
# -*- coding: utf-8 -*-

import multiprocessing
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
    # load libs
    from core.color import finish
    # load all modules in lib/brute, lib/scan, lib/graph
    module_names = load_all_modules()
    graph_names = load_all_graphs()

    # Parse ARGVs
    try:
        parser, options, startup_update_flag = load_all_args(module_names, graph_names)
    except SystemExit:
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
    socks_proxy = options.socks_proxy
    retries = options.retries
    graph_flag = options.graph_flag
    help_menu_flag = options.help_menu_flag
    ping_flag = options.ping_flag
    methods_args = options.methods_args
    method_args_list = options.method_args_list

    # Checking Requirements
    (targets, targets_list, thread_number, thread_number_host,
     log_in_file, scan_method, exclude_method, users, users_list,
     passwds, passwds_list, timeout_sec, ports, parser, module_names, language, verbose_level, show_version,
     check_update, socks_proxy, retries, graph_flag, help_menu_flag, methods_args, method_args_list) = \
        check_all_required(
            targets, targets_list, thread_number, thread_number_host,
            log_in_file, scan_method, exclude_method, users, users_list,
            passwds, passwds_list, timeout_sec, ports, parser, module_names, language, verbose_level, show_version,
            check_update, socks_proxy, retries, graph_flag, help_menu_flag, methods_args, method_args_list
        )

    info(messages(language, 0))
    # check for update
    if startup_update_flag is True:
        __version__, __code_name__ = _version_info()
        _check(__version__, __code_name__, language)

    info(messages(language, 96).format(len(load_all_modules()) - 1 + len(load_all_graphs())))
    suff = str(datetime.datetime.now()).replace(' ', '_').replace(':', '-') + '_' + ''.join(
        random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
    subs_temp = 'tmp/subs_temp_%s' % (suff)
    range_temp = 'tmp/ranges_%s' % (suff)
    total_targets = -1
    for total_targets, _ in enumerate(
            analysis(targets, check_ranges, check_subdomains, subs_temp, range_temp, log_in_file, time_sleep,
                     language, verbose_level, show_version, check_update, socks_proxy, retries)):
        pass
    total_targets += 1
    total_targets = total_targets * len(scan_method)
    targets = analysis(targets, check_ranges, check_subdomains, subs_temp, range_temp, log_in_file, time_sleep,
                       language, verbose_level, show_version, check_update, socks_proxy, retries)
    trying = 0
    for target in targets:
        for sm in scan_method:
            trying += 1
            p = multiprocessing.Process(target=start_attack, args=(
                str(target).rsplit()[0], trying, total_targets, sm, users, passwds, timeout_sec, thread_number,
                ports, log_in_file, time_sleep, language, verbose_level, show_version, check_update, socks_proxy,
                retries, ping_flag, methods_args))
            p.start()
            while 1:
                n = 0
                processes = multiprocessing.active_children()
                for process in processes:
                    if process.is_alive() is True:
                        n += 1
                    else:
                        processes.remove(process)
                if n >= thread_number_host:
                    time.sleep(0.01)
                else:
                    break

    while 1:
        try:
            exitflag = True
            for process in multiprocessing.active_children():
                if process.is_alive() is True:
                    exitflag = False
            time.sleep(0.01)
            if exitflag is True:
                break
        except KeyboardInterrupt:
            for process in multiprocessing.active_children():
                process.terminate()
            break
    info(messages(language, 42))
    os.remove(subs_temp)
    os.remove(range_temp)
    info(messages(language, 43))
    sort_logs(log_in_file, language, graph_flag)
    write('\n')
    info(messages(language, 44))
    write('\n\n')
    finish()
