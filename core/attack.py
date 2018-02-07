#!/usr/bin/env python
# -*- coding: utf-8 -*-

from core._die import __die_failure
from core.alert import info
from core.alert import messages


def start_attack(target, num, total, scan_method, users, passwds, timeout_sec, thread_number, ports, log_in_file,
                 time_sleep, language, verbose_level, socks_proxy, retries, ping_flag, methods_args, scan_id, scan_cmd):
    if verbose_level >= 1:
        info(messages(language, 45).format(str(target), str(num), str(total)))
    if ping_flag:
        import socks
        import socket
        from lib.icmp.engine import do_one as do_one_ping
        from lib.socks_resolver.engine import getaddrinfo
        from core.alert import warn
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
