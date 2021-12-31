#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from core.compatible import check_dependencies

"""
entry point of OWASP Nettacker framework
"""

# __check_external_modules created to check requirements before load the engine
if __name__ == "__main__":
    scan_unique_id = check_dependencies()  # check for dependencies

    # if dependencies and OS requirements are match then load the program
    import core.parse

    core.parse.load(scan_unique_id)  # load and parse the ARGV
    # sys.exit(main())
