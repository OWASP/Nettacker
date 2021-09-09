#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys


def die_success():
    """
    exit the framework with code 0
    """
    from core.color import reset_color
    reset_color()
    sys.exit(0)


def die_failure(msg):
    """
    exit the framework with code 1

    Args:
        msg: the error message
    """
    from core.color import reset_color
    from core.alert import error
    error(msg)
    reset_color()
    sys.exit(1)
