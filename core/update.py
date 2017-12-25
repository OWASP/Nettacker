#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
import socket
import socks
from core.alert import info
from core.alert import warn
from core.alert import messages
from core.compatible import version
from lib.socks_resolver.engine import getaddrinfo

url = 'http://nettacker.z3r0d4y.com/version.py'


def _update(__version__, __code_name__, language, socks_proxy):
    try:
        if socks_proxy is not None:
            socks_version = socks.SOCKS5 if socks_proxy.startswith('socks5://') else socks.SOCKS4
            socks_proxy = socks_proxy.rsplit('://')[1]
            socks.set_default_proxy(socks_version, str(socks_proxy.rsplit(':')[0]), int(socks_proxy.rsplit(':')[1]))
            socket.socket = socks.socksocket
            socket.getaddrinfo = getaddrinfo
        data = requests.get(url, headers={"User-Agent": "OWASP Nettacker"}).content
        if version() is 3:
            data = data.decode("utf-8")
        if __version__ + ' ' + __code_name__ == data.rsplit('\n')[0]:
            info(messages(language, 103))
        else:
            warn(messages(language, 101))
            warn(messages(language, 85))
    except:
        warn(messages(language, 102))
    return


def _check(__version__, __code_name__, language, socks_proxy):
    try:
        if socks_proxy is not None:
            socks_version = socks.SOCKS5 if socks_proxy.startswith('socks5://') else socks.SOCKS4
            socks_proxy = socks_proxy.rsplit('://')[1]
            socks.set_default_proxy(socks_version, str(socks_proxy.rsplit(':')[0]), int(socks_proxy.rsplit(':')[1]))
            socket.socket = socks.socksocket
            socket.getaddrinfo = getaddrinfo
        data = requests.get(url, headers={"User-Agent": "OWASP Nettacker"}).content
        if version() is 3:
            data = data.decode("utf-8")
        if __version__ + ' ' + __code_name__ == data.rsplit('\n')[0]:
            info(messages(language, 103))
        else:
            warn(messages(language, 101))
    except:
        warn(messages(language, 102))
    return
