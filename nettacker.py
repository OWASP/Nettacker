#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from core.load_modules import main
from core.load_modules import __check_external_modules

"""
entry point of OWASP Nettacker framework
"""

# __check_external_modules created to check requirements before load the engine
if __name__ == "__main__" and __check_external_modules():
    # from core.parse import load
    # load()  # load and parse the ARGV
    main()