#!/usr/bin/env python
# -*- coding: utf-8 -*-

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

    try:
        data = input(__input_msg(msg))
        if data == "":
            data = default
    except Exception:
        data = default
    except KeyboardInterrupt:
        print("\n")
        exit(1)

    return data
