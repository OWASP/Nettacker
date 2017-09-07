#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
from core.alert import *

__version__ = '0.0.1'
__code_name__ = 'SAME'


def logo():
    from core.alert import write
    from core import color
    write('''    
   ______          __      _____ _____  
  / __ \ \        / /\    / ____|  __ \ 
 | |  | \ \  /\  / /  \  | (___ | |__) |
 | |  | |\ \/  \/ / /\ \  \___ \|  ___/ 
 | |__| | \  /\  / ____ \ ____) | |     {2}Version {0}{3}  
  \____/   \/  \/_/    \_\_____/|_|     {4}{1}{5}
                          _   _      _   _             _            
                         | \ | |    | | | |           | |            
  {6}github.com/viraintel{7}   |  \| | ___| |_| |_ __ _  ___| | _____ _ __ 
  {8}owasp.org{9}              | . ` |/ _ \ __| __/ _` |/ __| |/ / _ \ '__|
  {10}viraintel.com{11}          | |\  |  __/ |_| || (_| | (__|   <  __/ |   
                         |_| \_|\___|\__|\__\__,_|\___|_|\_\___|_|   
                                               
    \n\n'''.format(__version__, __code_name__, color.color('red'), color.color('reset'), color.color('yellow'),
                   color.color('reset'), color.color('cyan'), color.color('reset'), color.color('cyan'),
                   color.color('reset'), color.color('cyan'), color.color('reset')))


def version():
    return int(sys.version_info[0])


def check(language):
    if 'linux' in sys.platform or 'darwin' in sys.platform:
        pass
        # os.system('clear')
    elif 'win32' == sys.platform or 'win64' == sys.platform:
        if language != 'en':
            from core.color import finish
            from core.alert import error
            error('please use english language on windows!')
            finish()
            sys.exit(1)
            # os.system('cls')
    else:
        error(messages(language, 47))
        from core.color import finish
        finish()
        sys.exit(1)
    if version() is 2 or version() is 3:
        pass
    else:
        error(messages(language, 48))
        from core.color import finish
        finish()
        sys.exit(1)
    logo()
    return


def os_name():
    return sys.platform
