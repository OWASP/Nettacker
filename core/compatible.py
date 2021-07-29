#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from core.alert import messages
from core.die import die_failure
from config import nettacker_paths


def version_info():
    """
    version information of the framework

    Returns:
        an array of version and code name
    """
    return open(nettacker_paths()['version_file']).read().split()


def logo():
    """
    OWASP Nettacker Logo
    """
    from core.alert import write_to_api_console
    from core import color
    from core.color import reset_color
    write_to_api_console(
        open(
            nettacker_paths()['logo_file']
        ).read().format(
            version_info()[0],
            version_info()[1],
            color.color('red'),
            color.color('reset'),
            color.color('yellow'),
            color.color('reset'),
            color.color('cyan'),
            color.color('reset'),
            color.color('cyan'),
            color.color('reset'),
            color.color('cyan'),
            color.color('reset')
        )
    )
    reset_color()


def python_version():
    """
    version of python

    Returns:
        integer version of python (2 or 3)
    """
    return int(sys.version_info[0])


def check_os_compatibility():
    """
    check if framework compatible with the OS

    Returns:
        True if compatible otherwise None
    """
    # from core.color import finish
    if not ('linux' in os_name() or 'darwin' in os_name()):
        die_failure(messages("error_platform"))
    return True


def os_name():
    """
    OS name

    Returns:
        OS name in string
    """
    return sys.platform
