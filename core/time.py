#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import datetime


def now(model="%Y-%m-%d %H:%M:%S"):
    """
    get now date and time
    Args:
        model:  the date and time model, default is "%Y-%m-%d %H:%M:%S"

    Returns:
        the date and time of now
    """
    return datetime.datetime.now().strftime(model) if model else datetime.datetime.now()
