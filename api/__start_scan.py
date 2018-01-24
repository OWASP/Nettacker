#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random
import os
import string
import multiprocessing
import sys
import time
from core.attack import start_attack
from core._time import now
from core.alert import info
from core.alert import messages
from core.alert import write
from core.targets import analysis
from core.log import sort_logs
from core.color import finish


def __scan(config, scan_id, scan_cmd):
    # Setting Variables
    targets = config["targets"]
    check_ranges = config["check_ranges"]
    check_subdomains = config["check_subdomains"]
    log_in_file = config["log_in_file"]
    time_sleep = config["time_sleep"]
    language = config["language"]
    verbose_level = config["verbose_level"]
    retries = config["retries"]
    socks_proxy = config["socks_proxy"]
    scan_method = config["scan_method"]
    users = config["users"]
    passwds = config["passwds"]
    timeout_sec = config["timeout_sec"]
    thread_number = config["thread_number"]
    ports = config["ports"]
    ping_flag = config["ping_flag"]
    methods_args = config["methods_args"]
    thread_number_host = config["thread_number_host"]
    graph_flag = config["graph_flag"]

    suff = now(model="%Y_%m_%d_%H_%M_%S") + "".join(random.choice(string.ascii_lowercase) for x in
                                                    range(10))
    subs_temp = "tmp/subs_temp_" + suff
    range_temp = "tmp/ranges_" + suff
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
    range_temp = "tmp/ranges_" + suff
    targets = analysis(targets, check_ranges, check_subdomains, subs_temp, range_temp, log_in_file, time_sleep,
                       language, verbose_level, retries, socks_proxy, False)
    trying = 0
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
    sort_logs(log_in_file, language, graph_flag)
    write("\n")
    info(messages(language, 44))
    write("\n\n")
    finish()
    return 1
