#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
from core.load_modules import main
from core.parse import load

"""
entry point of OWASP Nettacker framework
"""

# __check_external_modules created to check requirements before load the engine
if __name__ == "__main__":
    load()  # load and parse the ARGV
    # sys.exit(main())