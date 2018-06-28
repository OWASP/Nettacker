#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import socket

def recv_all(s, limit=4196):
    """
    receive all data from a socket

    Args:
        s: python socket
        limit: limit size to get response

    Returns:
        response or b""
    """
    response = ""
    while len(response) < limit:
        try:
            r = s.recv(1)
            if r != b"":
                response += r.decode()
            else:
                break
        except Exception as _:
            break
    return response

def conn(targ, port, timeout_sec, socks_proxy):
    """
    Socket Connection function
    Args:
        targ: Target host
        port: Target port
        timeout_sec: Timeout Seconds to wait for the connection
        socks_proxy: socks proxy connection details
    Returns:
        s: python socket
    """
    try:
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
                socket.getaddrinfo = getaddrinfo()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sys.stdout.flush()
        s.settimeout(timeout_sec)
        s.connect((targ, port))
        return s
    except Exception:
        return None

def kippo_detect(host, port, timeout, socks_proxy):
    try:
        s = conn(host, port, timeout, socks_proxy)
        banner = recv_all(s)
        s.send(banner + spacer)
        response = recv_all(s)
        if ('Protocol mismatch' in response or 'bad packet length' in response):
            return True
        else:
            return False
    except Exception as e:
        print e
