#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys


def __die_success():
    """
    exit the framework with code 0
    """
    from core.color import finish
    finish()
    sys.exit(0)


def __die_failure(msg):
    """
    exit the framework with code 1

    Args:
        msg: the error message
    """
    from core.color import finish
    from core.alert import error
    error(msg)
    finish()
    sys.exit(1)
