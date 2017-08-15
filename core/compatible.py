#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os


def version():
    return int(sys.version_info.major)


def check():
    if 'linux' in sys.platform or 'darwin' in sys.platform:
        os.system('clear')
    elif 'win32' == sys.platform or 'win64' == sys.platform:
        os.system('cls')
    else:
        sys.exit(
            'Sorry, This version of software just could be run on linux/osx/windows.')
    if version() is 2 or version() is 3:
        pass
    else:
        sys.exit('Your python version is not supported!')
    return


def os_name():
    return sys.platform
