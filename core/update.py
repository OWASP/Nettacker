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
from database.db import get_update_log
from database.db import save_update_log
from datetime import timedelta
from datetime import datetime

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

def _update_check(language):
    """
    This Function checks if an Update has happened in the previous day and if not, it checks for update

    Args:
        Language
    Return:
        True or False depending on if update should happen or not
    """
    try:
        logs = (get_update_log(language))
    except Exception:
        save_update_log(language)
        logs = (get_update_log(language))
    logs2 = (logs[len(logs)-1].last_update_time)
    if datetime.now() > datetime.strptime(logs2, "%Y-%m-%d %H:%M:%S.%f") + timedelta(days=1):
        save_update_log(language)
        return True
    else:
        return False

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
#    print(save_update_log(language))
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
