#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime


def now(model="%Y-%m-%d %H:%M:%S"):
    return datetime.datetime.now().strftime(model)
