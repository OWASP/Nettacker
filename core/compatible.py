#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
from core.alert import *
from core._die import __die_failure

__version__ = '0.0.1'
__code_name__ = 'SAME'


def _version_info():
    """
    version information of the framework

    Returns:
        an array of version and code name
    """
    return [__version__, __code_name__]


def logo():
    """
    OWASP Nettacker Logo
    """
    from core.alert import write_to_api_console
    from core import color
    from core.color import finish
    write_to_api_console('''    
   ______          __      _____ _____  
  / __ \ \        / /\    / ____|  __ \ 
 | |  | \ \  /\  / /  \  | (___ | |__) |
 | |  | |\ \/  \/ / /\ \  \___ \|  ___/ 
 | |__| | \  /\  / ____ \ ____) | |     {2}Version {0}{3}  
  \____/   \/  \/_/    \_\_____/|_|     {4}{1}{5}
                          _   _      _   _             _            
                         | \ | |    | | | |           | |            
  {6}github.com/zdresearch{7}  |  \| | ___| |_| |_ __ _  ___| | _____ _ __ 
  {8}owasp.org{9}              | . ` |/ _ \ __| __/ _` |/ __| |/ / _ \ '__|
  {10}zdresearch.com{11}         | |\  |  __/ |_| || (_| | (__|   <  __/ |   
                         |_| \_|\___|\__|\__\__,_|\___|_|\_\___|_|   
                                               
    \n\n'''.format(__version__, __code_name__, color.color('red'), color.color('reset'), color.color('yellow'),
                   color.color('reset'), color.color(
            'cyan'), color.color('reset'), color.color('cyan'),
                   color.color('reset'), color.color('cyan'), color.color('reset')))
    finish()


def version():
    """
    version of python

    Returns:
        integer version of python (2 or 3)
    """
    return int(sys.version_info[0])


def check(language):
    """
    check if framework compatible with the OS
    Args:
        language: language

    Returns:
        True if compatible otherwise None
    """
    # from core.color import finish
    if 'linux' in os_name() or 'darwin' in os_name():
        pass
        # os.system('clear')
    elif 'win32' == os_name() or 'win64' == os_name():
        # if language != 'en':
        #    from core.color import finish
        #    from core.alert import error
        #   error('please use english language on windows!')
        #    finish()
        #    sys.exit(1)
        # os.system('cls')
        pass
    else:
        __die_failure(messages(language, "error_platform"))
    if version() is 2 or version() is 3:
        pass
    else:
        __die_failure(messages(language, "python_version_error"))
    logo()
    return True


def os_name():
    """
    OS name

    Returns:
        OS name in string
    """
    return sys.platform


def is_windows():
    """
    check if the framework run in Windows OS

    Returns:
        True if its running on windows otherwise False
    """
    if 'win32' == os_name() or 'win64' == os_name():
        return True
    return False
