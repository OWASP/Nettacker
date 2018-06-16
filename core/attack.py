#!/usr/bin/env python
# -*- coding: utf-8 -*-

import multiprocessing
import threading
import time
import os
import random
import string
import sys
import socks
import socket
from core._die import __die_failure
from core.alert import info
from core.alert import messages
from core._time import now
from core.load_modules import load_file_path
from core.log import sort_logs
from core.targets import analysis
from core.alert import write
from core.color import finish
from lib.icmp.engine import do_one as do_one_ping
from lib.socks_resolver.engine import getaddrinfo
from core.alert import warn

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def start_attack(target, num, total, scan_method, users, passwds, timeout_sec, thread_number, ports, log_in_file,
                 time_sleep, language, verbose_level, socks_proxy, retries, ping_flag, methods_args, scan_id, scan_cmd):
    """
    start new attack for each target

    Args:
        target: target
        num: number of process
        total: number of total processes
        scan_method: module name
        users: usernames
        passwds: passwords
        timeout_sec: timeout seconds
        thread_number: thread number
        ports: port numbers
        log_in_file: output filename
        time_sleep: time sleep
        language: language
        verbose_level: verbose level number
        socks_proxy: socks proxy
        retries: number of retries
        ping_flag: ping before scan flag
        methods_args: module name
        scan_id: scan hash id
        scan_cmd: scan cmd

    Returns:
        True of success otherwise None
    """
    if verbose_level >= 1:
        info(messages(language, "start_attack").format(
            str(target), str(num), str(total)))
    if ping_flag:
        if socks_proxy is not None:
            socks_version = socks.SOCKS5 if socks_proxy.startswith(
                'socks5://') else socks.SOCKS4
            socks_proxy = socks_proxy.rsplit('://')[1]
            if '@' in socks_proxy:
                socks_username = socks_proxy.rsplit(':')[0]
                socks_password = socks_proxy.rsplit(':')[1].rsplit('@')[0]
                socks.set_default_proxy(socks_version, str(socks_proxy.rsplit('@')[1].rsplit(':')[0]),
                                        int(socks_proxy.rsplit(':')[-1]), username=socks_username,
                                        password=socks_password)
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo
            else:
                socks.set_default_proxy(socks_version, str(socks_proxy.rsplit(':')[0]),
                                        int(socks_proxy.rsplit(':')[1]))
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo
        if do_one_ping(target, timeout_sec, 8) is None:
            if verbose_level >= 3:
                warn(messages(language, "skipping_target").format(
                    target, scan_method))
            return None
    # Calling Engines
    try:
        start = getattr(
                __import__('lib.{0}.{1}.engine'.format(scan_method.rsplit('_')[-1], '_'.join(scan_method.rsplit('_')[:-1])),
                       fromlist=['start']), 'start')
    except:
        __die_failure(
            messages(language, "module_not_available").format(scan_method))
    start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd)
    return True


def __go_for_attacks(targets, check_ranges, check_subdomains, log_in_file, time_sleep, language, verbose_level, retries,
                     socks_proxy, users, passwds, timeout_sec, thread_number, ports, ping_flag, methods_args,
                     backup_ports, scan_method, thread_number_host, graph_flag, profile,
                     api_flag, scan_id=None):
    """
    preparing for attacks and managing multi-processing for host

    Args:
        targets: list of calculated targets
        check_ranges: check IP range flag
        check_subdomains: check subdomain flag
        log_in_file: output filename
        time_sleep: time sleep seconds
        language: language
        verbose_level: verbose level number
        retries: retries number
        socks_proxy: socks proxy address
        users: usernames
        passwds: passwords
        timeout_sec: timeout seconds
        thread_number: thread numbers
        ports: port numbers
        ping_flag: ping before scan flag
        methods_args: method args for modules
        backup_ports: port numbers (backup)
        scan_method: selected module names
        thread_number_host: threads for hosts scan
        graph_flag: graph name
        profile: profile name
        api_flag: API flag

    Returns:
        True when it ends
    """
    suff = now(model="%Y_%m_%d_%H_%M_%S") + "".join(random.choice(string.ascii_lowercase) for x in
                                                    range(10))
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
    if scan_id is None:
        scan_id = "".join(random.choice("0123456789abcdef") for x in range(32))
    scan_cmd = messages(
        language, "through_API") if api_flag else " ".join(sys.argv)
    for target in targets:
        for sm in scan_method:
            trying += 1
            p = multiprocessing.Process(target=start_attack, args=(
                str(target).rsplit()[
                    0], trying, total_targets, sm, users, passwds, timeout_sec, thread_number,
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
                info(messages(language, "waiting").format(
                    ", ".join([p.name for p in multiprocessing.active_children()])))
            time.sleep(0.01)
            if exitflag:
                break
        except KeyboardInterrupt:
            for process in multiprocessing.active_children():
                process.terminate()
            break
    info(messages(language, "remove_temp"))
    os.remove(subs_temp)
    os.remove(range_temp)
    info(messages(language, "sorting_results"))
    sort_logs(log_in_file, language, graph_flag, scan_id, scan_cmd, verbose_level, 0, profile, scan_method,
              backup_ports)
    write("\n")
    info(messages(language, "done"))
    write("\n\n")
    finish()
    return True
