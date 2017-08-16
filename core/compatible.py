#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
from core.alert import *

def version():
    return int(sys.version_info.major)


def check(language):
    if 'linux' in sys.platform or 'darwin' in sys.platform:
        os.system('clear')
    elif 'win32' == sys.platform or 'win64' == sys.platform:
        os.system('cls')
    else:
        sys.exit(error(messages(language,47)))
    if version() is 2 or version() is 3:
        pass
    else:
        sys.exit(error(messages(language,48)))
    return


def os_name():
    return sys.platform
