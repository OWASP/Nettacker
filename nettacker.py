#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from core.compatible import check_dependencies

"""
entry point of OWASP Nettacker framework
"""

# __check_external_modules created to check requirements before load the engine
if __name__ == "__main__":
    check_dependencies()  # check for dependencies

    # if dependencies and OS requirements are match then load the program
    from core.parse import load
    import sys

    # Example commands to demonstrate OWASP Nettacker functionalities
    example_commands = [
        "-i target.com",
        "-i target.com -v --start-api --api-host 0.0.0.0 --api-port 5000",
        "-i target.com -m ftp_brute,ssh_brute",
        "-i target.com -o results.txt -L en",
        "-i target.com -u admin -P passwords.txt",
        "-i target.com -g 21,22 -p tcp,udp",
        "-i target.com --start-api --api-host 192.168.1.100 --api-port 8080 --api-ssl",
        "-i target.com -m http_crawl -f --crawl-depth 3",
        "-i target.com --db-save --db-name nettacker_results"
    ]

    # Print example commands
    print("Example commands:")
    for command in example_commands:
        print(f"nettacker {command}")

    # Load and parse the ARGV
    load()
    # sys.exit(main())
