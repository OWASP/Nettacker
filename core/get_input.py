#!/usr/bin/env python
# -*- coding: utf-8 -*-

from core.compatible import version
from core.alert import __input_msg


def __input(msg, default):
    """
    get input in CLI

    Args:
        msg: a message to alert
        default: default value if user entered (empty)

    Returns:
        user input content
    """
    if version() is 2:
        try:
            data = raw_input(__input_msg(msg))
            if data == '':
                data = default
        except:
            data = default
    else:
        try:
            data = input(__input_msg(msg))
            if data == '':
                data = default
        except:
            data = default
    return data
