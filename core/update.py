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
    """
    update the framework

    Args:
        __version__: version number
        __code_name__: code name
        language: language
        socks_proxy: socks proxy

    Returns:
        True if success otherwise None
    """
    try:
        if socks_proxy is not None:
            socks_version = socks.SOCKS5 if socks_proxy.startswith(
                'socks5://') else socks.SOCKS4
            socks_proxy = socks_proxy.rsplit('://')[1]
            socks.set_default_proxy(socks_version, str(
                socks_proxy.rsplit(':')[0]), int(socks_proxy.rsplit(':')[1]))
            socket.socket = socks.socksocket
            socket.getaddrinfo = getaddrinfo
        data = requests.get(
            url, headers={"User-Agent": "OWASP Nettacker"}).content
        if version() is 3:
            data = data.decode("utf-8")
        if __version__ + ' ' + __code_name__ == data.rsplit('\n')[0]:
            info(messages(language, "last_version"))
        else:
            warn(messages(language, "not_last_version"))
            warn(messages(language, "feature_unavailable"))
    except:
        warn(messages(language, "cannot_update"))
    return True


def _check(__version__, __code_name__, language, socks_proxy):
    """
    check for update

    Args:
        __version__: version number
        __code_name__: code name
        language: language
        socks_proxy: socks proxy

    Returns:
        True if success otherwise None
    """
    try:
        if socks_proxy is not None:
            socks_version = socks.SOCKS5 if socks_proxy.startswith(
                'socks5://') else socks.SOCKS4
            socks_proxy = socks_proxy.rsplit('://')[1]
            socks.set_default_proxy(socks_version, str(
                socks_proxy.rsplit(':')[0]), int(socks_proxy.rsplit(':')[1]))
            socket.socket = socks.socksocket
            socket.getaddrinfo = getaddrinfo
        data = requests.get(
            url, headers={"User-Agent": "OWASP Nettacker"}).content
        if version() is 3:
            data = data.decode("utf-8")
        if __version__ + ' ' + __code_name__ == data.rsplit('\n')[0]:
            info(messages(language, "last_version"))
        else:
            warn(messages(language, "not_last_version"))
    except:
        warn(messages(language, "cannot_update"))
    return True
