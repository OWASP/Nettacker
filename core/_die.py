#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys


def __die_success():
    from core.color import finish
    finish()
    sys.exit(0)


def __die_failure(msg):
    from core.color import finish
    from core.alert import error
    error(msg)
    finish()
    sys.exit(1)
