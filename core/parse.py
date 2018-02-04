#!/usr/bin/env python
# -*- coding: utf-8 -*-

import multiprocessing
import time
import os
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
from core.load_modules import load_file_path
from core.args_loader import load_all_args
from core.args_loader import check_all_required
from core.update import _check
from core.compatible import _version_info
from core._time import now


def load():
    write("\n\n")
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
    thread_number = options.thread_number + 1
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
    wizard_mode = options.wizard_mode
    profile = options.profile
    start_api = options.start_api
    api_host = options.api_host
    api_port = options.api_port
    api_debug_mode = options.api_debug_mode
    api_access_key = options.api_access_key
    api_client_white_list = options.api_client_white_list
    api_client_white_list_ips = options.api_client_white_list_ips
    api_access_log = options.api_access_log
    api_access_log_filename = options.api_access_log_filename
    backup_ports = ports

    # Checking Requirements
    (targets, targets_list, thread_number, thread_number_host,
     log_in_file, scan_method, exclude_method, users, users_list,
     passwds, passwds_list, timeout_sec, ports, parser, module_names, language, verbose_level, show_version,
     check_update, socks_proxy, retries, graph_flag, help_menu_flag, methods_args, method_args_list, wizard_mode,
     profile, start_api, api_host, api_port, api_debug_mode, api_access_key, api_client_white_list,
     api_client_white_list_ips, api_access_log, api_access_log_filename) = \
        check_all_required(
            targets, targets_list, thread_number, thread_number_host,
            log_in_file, scan_method, exclude_method, users, users_list,
            passwds, passwds_list, timeout_sec, ports, parser, module_names, language, verbose_level, show_version,
            check_update, socks_proxy, retries, graph_flag, help_menu_flag, methods_args, method_args_list, wizard_mode,
            profile, start_api, api_host, api_port, api_debug_mode, api_access_key, api_client_white_list,
            api_client_white_list_ips, api_access_log, api_access_log_filename
        )

    info(messages(language, 0))
    # check for update
    if startup_update_flag:
        __version__, __code_name__ = _version_info()
        _check(__version__, __code_name__, language, socks_proxy)

    info(messages(language, 96).format(len(load_all_modules()) - 1 + len(load_all_graphs())))
    suff = now(model="%Y_%m_%d_%H_%M_%S") + "".join(random.choice(string.ascii_lowercase) for x in
                                                    range(10))
    filepath = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    subs_temp = "{}/tmp/subs_temp_".format(load_file_path()) + suff
    range_temp = "{}/tmp/ranges_".format(load_file_path()) + suff
    total_targets = -1
    for total_targets, _ in enumerate(
            analysis(targets, check_ranges, check_subdomains, subs_temp, range_temp, log_in_file, time_sleep,
                     language, verbose_level, retries, socks_proxy, True)):
        pass
    total_targets += 1
    total_targets = total_targets * len(scan_method)
    try:
        os.remove(range_temp)
    except:
        pass
    range_temp = "{}/tmp/ranges_".format(load_file_path()) + suff
    targets = analysis(targets, check_ranges, check_subdomains, subs_temp, range_temp, log_in_file, time_sleep,
                       language, verbose_level, retries, socks_proxy, False)
    trying = 0
    scan_id = "".join(random.choice("0123456789abcdef") for x in range(32))
    scan_cmd = " ".join(sys.argv)
    for target in targets:
        for sm in scan_method:
            trying += 1
            p = multiprocessing.Process(target=start_attack, args=(
                str(target).rsplit()[0], trying, total_targets, sm, users, passwds, timeout_sec, thread_number,
                ports, log_in_file, time_sleep, language, verbose_level, socks_proxy, retries, ping_flag, methods_args,
                scan_id, scan_cmd))
            p.name = str(target) + "->" + sm
            p.start()
            while 1:
                n = 0
                processes = multiprocessing.active_children()
                for process in processes:
                    if process.is_alive():
                        n += 1
                    else:
                        processes.remove(process)
                if n >= thread_number_host:
                    time.sleep(0.01)
                else:
                    break
    _waiting_for = 0
    while 1:
        try:
            exitflag = True
            if len(multiprocessing.active_children()) is not 0:
                exitflag = False
                _waiting_for += 1
            if _waiting_for > 3000:
                _waiting_for = 0
                info(messages(language, 138).format(", ".join([p.name for p in multiprocessing.active_children()])))
            time.sleep(0.01)
            if exitflag:
                break
        except KeyboardInterrupt:
            for process in multiprocessing.active_children():
                process.terminate()
            break
    info(messages(language, 42))
    os.remove(subs_temp)
    os.remove(range_temp)
    info(messages(language, 43))
    sort_logs(log_in_file, language, graph_flag, scan_id, scan_cmd, verbose_level, 0, profile, scan_method, backup_ports)
    write("\n")
    info(messages(language, 44))
    write("\n\n")
    finish()
