#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
