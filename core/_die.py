#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from core.color import finish


def __die_success():
    finish()
    sys.exit(0)


def __die_failure(msg):
    from core.alert import error
    error(msg)
    finish()
    sys.exit(1)
