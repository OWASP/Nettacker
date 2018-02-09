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


def remove_finish_threads():
    time.sleep(1)
    kill_threads = {}
    while 1:
        time.sleep(0.1)
        from lib import threads_counter
        threads = dict(threads_counter.active_threads)
        print threads_counter.active_threads, kill_threads
        for t in threads:
            try:
                if '->' in t and threads_counter.active_threads[t] is 0:
                    try:
                        if kill_threads[t] is 3:
                            threads_counter.active_threads.pop(t)
                            kill_threads.pop(t)
                        else:
                            kill_threads[t] += 1
                    except:
                        kill_threads[t] = 0
                else:
                    kill_threads[t] = 0
            except:
                pass
        if len(threads_counter.active_threads) is 0:
            return True


def multi_thread_open(targets, scan_method, total_targets, users, passwds, timeout_sec, thread_number, ports,
                      log_in_file, time_sleep, language, verbose_level, socks_proxy, retries, ping_flag, methods_args,
                      scan_id, scan_cmd, thread_number_host):
    from lib import threads_counter
    kill_t = threading.Thread(target=remove_finish_threads)
    kill_t.start()
    trying = 0
    for target in targets:
        target = str(target)
        try:
            threads_counter.active_threads[target]
        except:
            threads_counter.active_threads[target] = 0
        for sm in scan_method:
            try:
                threads_counter.active_threads[target + '->' + sm]
            except:
                threads_counter.active_threads[target + '->' + sm] = 0
            trying += 1
            threading.Thread(target=start_attack, args=(
                target.rsplit()[0], trying, total_targets, sm, users, passwds, timeout_sec, thread_number,
                ports, log_in_file, time_sleep, language, verbose_level, socks_proxy, retries, ping_flag, methods_args,
                scan_id, scan_cmd), name=str(target) + "->" + sm).start()
            while 1:
                try:
                    if threads_counter.active_threads[target] <= thread_number_host:
                        break
                    time.sleep(0.01)
                except KeyboardInterrupt:
                    for t in threading.enumerate():
                        t._Thread__stop()
                    return
    _waiting_for = 0
    while 1:
        try:
            _waiting_for += 1
            # refresh lib
            from lib import threads_counter
            if threading.activeCount() is 2:
                try:
                    kill_t._Thread__stop()
                except:
                    pass
                return
            if _waiting_for > 3000:
                _waiting_for = 0
                msg = messages(language, 138).format(
                    ", ".join([t for t in threads_counter.active_threads if '->' in t]))
                if len(msg) > 70:
                    msg = msg[0:70] + '...'
                info(msg)
            time.sleep(0.01)
        except KeyboardInterrupt:
            for t in threading.enumerate():
                t._Thread__stop()
            return


def multi_process_open(targets, scan_method, total_targets, users, passwds, timeout_sec, thread_number, ports,
                       log_in_file, time_sleep, language, verbose_level, socks_proxy, retries, ping_flag, methods_args,
                       scan_id, scan_cmd, thread_number_host):
    trying = 0
    for target in targets:
        for sm in scan_method:
            trying += 1
            multiprocessing.Process(target=start_attack, args=(
                str(target).rsplit()[0], trying, total_targets, sm, users, passwds, timeout_sec, thread_number,
                ports, log_in_file, time_sleep, language, verbose_level, socks_proxy, retries, ping_flag, methods_args,
                scan_id, scan_cmd), name=str(target) + "->" + sm).start()
            while 1:
                try:
                    if len(multiprocessing.active_children()) < thread_number_host:
                        break
                    time.sleep(0.01)
                except KeyboardInterrupt:
                    for process in multiprocessing.active_children():
                        process.terminate()
                    break
    _waiting_for = 0
    while 1:
        try:
            _waiting_for += 1
            if len(multiprocessing.active_children()) is 0:
                break
            if _waiting_for > 3000:
                _waiting_for = 0
                info(messages(language, 138).format(", ".join([p.name for p in multiprocessing.active_children()])))
            time.sleep(0.01)
        except KeyboardInterrupt:
            for process in multiprocessing.active_children():
                process.terminate()
            break


def start_attack(target, num, total, scan_method, users, passwds, timeout_sec, thread_number, ports, log_in_file,
                 time_sleep, language, verbose_level, socks_proxy, retries, ping_flag, methods_args, scan_id, scan_cmd):
    if verbose_level >= 1:
        info(messages(language, 45).format(str(target), str(num), str(total)))
    if ping_flag:
        if socks_proxy is not None:
            socks_version = socks.SOCKS5 if socks_proxy.startswith('socks5://') else socks.SOCKS4
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
                warn(messages(language, 100).format(target, scan_method))
            return None
    # Calling Engines
    try:
        start = getattr(
            __import__('lib.{0}.{1}.engine'.format(scan_method.rsplit('_')[-1], '_'.join(scan_method.rsplit('_')[:-1])),
                       fromlist=['start']), 'start')
    except:
        __die_failure(messages(language, 46).format(scan_method))
    start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd)
    return 0


def __go_for_attacks(targets, check_ranges, check_subdomains, log_in_file, time_sleep, language, verbose_level, retries,
                     socks_proxy, users, passwds, timeout_sec, thread_number, ports, ping_flag, methods_args,
                     multi_process_engine, backup_ports, scan_method, thread_number_host, graph_flag, profile,
                     api_flag):
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
    scan_id = "".join(random.choice("0123456789abcdef") for x in range(32))
    scan_cmd = messages(language, 158) if api_flag else " ".join(sys.argv)
    if multi_process_engine:
        multi_process_open(targets, scan_method, total_targets, users, passwds, timeout_sec, thread_number, ports,
                           log_in_file, time_sleep, language, verbose_level, socks_proxy, retries, ping_flag,
                           methods_args, scan_id, scan_cmd, thread_number_host)
    else:
        multi_thread_open(targets, scan_method, total_targets, users, passwds, timeout_sec, thread_number, ports,
                          log_in_file, time_sleep, language, verbose_level, socks_proxy, retries, ping_flag,
                          methods_args, scan_id, scan_cmd, thread_number_host)
    info(messages(language, 42))
    os.remove(subs_temp)
    os.remove(range_temp)
    info(messages(language, 43))
    sort_logs(log_in_file, language, graph_flag, scan_id, scan_cmd, verbose_level, 0, profile, scan_method,
              backup_ports)
    write("\n")
    info(messages(language, 44))
    write("\n\n")
    finish()
    return True
