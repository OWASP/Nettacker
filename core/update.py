#!/usr/bin/env python
# -*- coding: utf-8 -*-

from core.alert import info
from core.alert import warn
from core.alert import messages
from core.compatible import version

url = 'http://nettacker.z3r0d4y.com/version.py'


def _update(__version__, __code_name__, language):
    from core.compatible import version
    if version() is 2:
        from urllib import urlopen
    if version() is 3:
        from urllib.request import urlopen
    try:
        data = urlopen(url).read()
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


def _check(__version__, __code_name__, language):
    from core.compatible import version
    if version() is 2:
        from urllib import urlopen
    if version() is 3:
        from urllib.request import urlopen
    try:
        data = urlopen(url).read()
        if version() is 3:
            data = data.decode("utf-8")
        if __version__ + ' ' + __code_name__ == data.rsplit('\n')[0]:
            info(messages(language, 103))
        else:
            warn(messages(language, 101))
    except:
        warn(messages(language, 102))
    return
