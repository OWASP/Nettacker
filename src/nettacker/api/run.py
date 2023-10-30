#!/usr/bin/env python3

from nettacker.core.compatible import check_dependencies

"""
entry point of OWASP Nettacker framework
"""

# __check_external_modules created to check requirements before load the engine
if __name__ == "__main__":
    check_dependencies()  # check for dependencies

    # if dependencies and OS requirements are match then load the program
    from nettacker.core.parse import load

    load()  # load and parse the ARGV
    # sys.exit(main())
