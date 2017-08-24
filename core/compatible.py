#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
from core.alert import *

__version__ = '0.1'
__code_name__ = 'SAME'


def logo():
    from core.alert import write
    write('''    
   ______          __      _____ _____  
  / __ \ \        / /\    / ____|  __ \ 
 | |  | \ \  /\  / /  \  | (___ | |__) |
 | |  | |\ \/  \/ / /\ \  \___ \|  ___/ 
 | |__| | \  /\  / ____ \ ____) | |     Version {0}  
  \____/   \/  \/_/    \_\_____/|_|     {1}
                          _   _      _   _             _            
                         | \ | |    | | | |           | |            
  github.com/viraintel   |  \| | ___| |_| |_ __ _  ___| | _____ _ __ 
  owasp.org              | . ` |/ _ \ __| __/ _` |/ __| |/ / _ \ '__|
  viraintel.com          | |\  |  __/ |_| || (_| | (__|   <  __/ |   
                         |_| \_|\___|\__|\__\__,_|\___|_|\_\___|_|   
                                               
    \n\n'''.format(__version__,__code_name__))


def version():
    return int(sys.version_info[0])


def check(language):
    if 'linux' in sys.platform or 'darwin' in sys.platform:
        pass
        # os.system('clear')
    elif 'win32' == sys.platform or 'win64' == sys.platform:
        pass
        # os.system('cls')
    else:
        sys.exit(error(messages(language, 47)))
    if version() is 2 or version() is 3:
        pass
    else:
        sys.exit(error(messages(language, 48)))
    logo()
    return


def os_name():
    return sys.platform
