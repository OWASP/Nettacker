#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import os
import socks
import json
from core.targets import target_type
from core.alert import info
from core.alert import messages
from core.alert import warn
from lib.icmp.engine import send_one_ping, receive_one_ping
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.log import __log_into_file


def extra_requirements_dict():
    return {}


def do_one_ping(dest_addr, timeout, psize):
    """
    Returns either the delay (in seconds) or none on timeout.
    """
    icmp = socket.getprotobyname("icmp")
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    except socket.error:
        return None

    my_id = os.getpid() & 0xFFFF

    send_one_ping(my_socket, dest_addr, my_id, psize)
    delay = receive_one_ping(my_socket, my_id, timeout)

    my_socket.close()
    return delay


def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(
            target) != 'HTTP' or target_type(target) != 'SINGLE_IPv6':
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
        n = 0
        # warning for each target make the screen so messy in IP ranges
        # warn(messages(language,"root_required"))
        while 1:
            r = do_one_ping(target, timeout_sec, 84)
            if r is None:
                n = n + 1
                if n == retries:
                    if verbose_level > 3:
                        warn(messages(language, "host_down").format(target))
                    if verbose_level is not 0:
                        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': '',
                                           'TYPE': 'icmp scan',
                                           'DESCRIPTION': messages(language, "host_down").format(target),
                                           'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id,
                                           'SCAN_CMD': scan_cmd}) + "\n"
                        __log_into_file(log_in_file, 'a', data, language)
                    break
                else:
                    pass
            else:
                info(messages(language, "host_up").format(
                    target, str(round(r * 1000, 2)) + "ms"))
                data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': '',
                                   'TYPE': 'icmp scan',
                                   'DESCRIPTION': messages(language, "host_up").format(target,
                                                                                       str(round(r * 1000, 2)) + "ms"),
                                   'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id,
                                   'SCAN_CMD': scan_cmd}) + "\n"
                __log_into_file(log_in_file, 'a', data, language)
                break
    else:
        warn(messages(language, "input_target_error").format('icmp_scan', target))
