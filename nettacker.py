#!/usr/bin/env python
# -*- coding: utf-8 -*-

from core.load_modules import __check_external_modules
from core.parse import load

"""
entry point of OWASP Nettacker framework
"""

# __check_external_modules created to check requirements before load the engine
if __name__ == "__main__" and __check_external_modules():
    load()  # load and parse the ARGV
