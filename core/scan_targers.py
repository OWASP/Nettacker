#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import multiprocessing
import time
import os
import sys
import socks
import socket
from core.die import die_failure
from core.alert import info
from core.alert import messages
from core.log import sort_logs
from core.targets import analysis
from core.alert import write
from core.color import reset_color
from lib.icmp.engine import do_one as do_one_ping
from lib.socks_resolver.engine import getaddrinfo
from core.alert import warn
from core.utility import generate_random_token


def start_attack(
        target,
        num,
        total,
        selected_modules,
        usernames,
        passwords,
        timeout_sec,
        thread_per_host,
        ports,
        output_file,
        time_sleep_between_requests,
        language,
        verbose_mode,
        socks_proxy,
        retries,
        ping_before_scan,
        scan_id,
        scan_cmd,
):
    """
    start new attack for each target

    Args:
        target: target
        num: number of process
        total: number of total processes
        selected_modules: module name
        usernames: usernames
        passwords: passwords
        timeout_sec: timeout seconds
        thread_per_host: thread number
        ports: port numbers
        output_file: output filename
        time_sleep_between_requests: time sleep
        language: language
        verbose_mode: verbose level number
        socks_proxy: socks proxy
        retries: number of retries
        ping_before_scan: ping before scan flag
        scan_id: scan hash id
        scan_cmd: scan cmd

    Returns:
        True of success otherwise None
    """
    if verbose_mode >= 1:
        info(
            messages("start_attack").format(
                str(target), str(num), str(total)
            )
        )
    if ping_before_scan:
        if socks_proxy is not None:
            socks_version = (
                socks.SOCKS5
                if socks_proxy.startswith("socks5://")
                else socks.SOCKS4
            )
            socks_proxy = socks_proxy.rsplit("://")[1]
            if "@" in socks_proxy:
                socks_username = socks_proxy.rsplit(":")[0]
                socks_password = socks_proxy.rsplit(":")[1].rsplit("@")[0]
                socks.set_default_proxy(
                    socks_version,
                    str(socks_proxy.rsplit("@")[1].rsplit(":")[0]),
                    int(socks_proxy.rsplit(":")[-1]),
                    username=socks_username,
                    password=socks_password,
                )
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo
            else:
                socks.set_default_proxy(
                    socks_version,
                    str(socks_proxy.rsplit(":")[0]),
                    int(socks_proxy.rsplit(":")[1]),
                )
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo
        if do_one_ping(target, timeout_sec, 8) is None:
            if verbose_mode >= 3:
                warn(
                    messages("skipping_target").format(
                        target, selected_modules
                    )
                )
            return None
    # Calling Engines
    try:
        start = getattr(
            __import__(
                "lib.{0}.{1}.engine".format(
                    selected_modules.rsplit("_")[-1],
                    "_".join(selected_modules.rsplit("_")[:-1]),
                ),
                fromlist=["start"],
            ),
            "start",
        )
    except Exception:
        die_failure(
            messages("module_not_available").format(selected_modules)
        )
    start(
        target,
        usernames,
        passwords,
        ports,
        timeout_sec,
        thread_per_host,
        num,
        total,
        output_file,
        time_sleep_between_requests,
        language,
        verbose_mode,
        socks_proxy,
        retries,
        scan_id,
        scan_cmd,
    )
    return True


def start_scan_processes(options):
    """
    preparing for attacks and managing multi-processing for host

    Args:
        options: all options

    Returns:
        True when it ends
    """
    scan_unique_id = generate_random_token(32)
    # find total number of targets + types + expand (subdomain, IPRanges, etc)
    targets = analysis(options)
    trying = 0
    scan_cmd = (
        messages("through_API") if options.start_api_server else " ".join(sys.argv)
    )
    for target in targets:
        for sm in options.selected_modules:
            trying += 1
            p = multiprocessing.Process(
                target=start_attack,
                args=(
                    str(target).rsplit()[0],
                    trying,
                    total_targets,
                    sm,
                    usernames,
                    passwords,
                    timeout_sec,
                    thread_per_host,
                    ports,
                    output_file,
                    time_sleep_between_requests,
                    language,
                    verbose_mode,
                    socks_proxy,
                    retries,
                    ping_before_scan,
                    scan_id,
                    scan_cmd,
                ),
            )
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
                if n >= parallel_host_scan:
                    time.sleep(0.01)
                else:
                    break
    _waiting_for = 0
    while 1:
        try:
            exitflag = True
            if len(multiprocessing.active_children()) != 0:
                exitflag = False
                _waiting_for += 1
            if _waiting_for > 3000:
                _waiting_for = 0
                info(
                    messages("waiting").format(
                        ", ".join(
                            [t.name for t in multiprocessing.active_children()]
                        )
                    )
                )
            time.sleep(0.01)
            if exitflag:
                break
        except KeyboardInterrupt:
            for process in multiprocessing.active_children():
                process.terminate()
            break
    info(messages("remove_temp"))
    os.remove(subs_temp)
    os.remove(range_temp)
    info(messages("sorting_results"))
    sort_logs(
        output_file,
        language,
        graph_name,
        scan_id,
        scan_cmd,
        verbose_mode,
        0,
        None,
        selected_modules,
        backup_ports,
    )
    write("\n")
    info(messages("done"))
    write("\n\n")
    reset_color()
    return True
