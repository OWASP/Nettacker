#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
from core.die import die_failure
from config import nettacker_paths


def version_info():
    """
    version information of the framework

    Returns:
        an array of version and code name
    """
    return open(nettacker_paths()['version_file']).read().split()


def logo():
    """
    OWASP Nettacker Logo
    """
    from core.alert import write_to_api_console
    from core import color
    from core.color import reset_color
    write_to_api_console(
        open(
            nettacker_paths()['logo_file']
        ).read().format(
            version_info()[0],
            version_info()[1],
            color.color('red'),
            color.color('reset'),
            color.color('yellow'),
            color.color('reset'),
            color.color('cyan'),
            color.color('reset'),
            color.color('cyan'),
            color.color('reset'),
            color.color('cyan'),
            color.color('reset')
        )
    )
    reset_color()


def python_version():
    """
    version of python

    Returns:
        integer version of python (2 or 3)
    """
    return int(sys.version_info[0])


def os_name():
    """
    OS name

    Returns:
        OS name in string
    """
    return sys.platform


def check_dependencies():
    if python_version() == 2:
        sys.exit("Python2 is No longer supported!")

    # check os compatibility
    external_modules = open(nettacker_paths()["requirements_path"]).read().split('\n')
    for module_name in external_modules:
        try:
            __import__(
                module_name.split('==')[0] if 'library_name=' not in module_name
                else module_name.split('library_name=')[1].split()[0]
            )
        except Exception:
            if 'is_optional=true' not in module_name:
                sys.exit(
                    "pip3 install -r requirements.txt ---> " +
                    module_name + " not installed!"
                )
    logo()

    from core.alert import messages
    if not ('linux' in os_name() or 'darwin' in os_name()):
        die_failure(messages("error_platform"))

    if not os.path.exists(nettacker_paths["home_path"]):
        try:
            os.mkdir(nettacker_paths["home_path"])
            os.mkdir(nettacker_paths["tmp_path"])
            os.mkdir(nettacker_paths["results_path"])
        except Exception:
            die_failure("cannot access the directory {0}".format(
                nettacker_paths["home_path"])
            )
    if not os.path.exists(nettacker_paths["tmp_path"]):
        try:
            os.mkdir(nettacker_paths["tmp_path"])
        except Exception:
            die_failure("cannot access the directory {0}".format(
                nettacker_paths["results_path"])
            )
    if not os.path.exists(nettacker_paths["results_path"]):
        try:
            os.mkdir(nettacker_paths["results_path"])
        except Exception:
            die_failure("cannot access the directory {0}".format(
                nettacker_paths["results_path"])
            )

    if nettacker_paths["database_type"] == "sqlite":
        try:
            if not os.path.isfile(nettacker_paths["database_path"]):
                from database.sqlite_create import sqlite_create_tables
                sqlite_create_tables()
        except Exception:
            die_failure("cannot access the directory {0}".format(
                nettacker_paths["home_path"])
            )
    elif nettacker_paths["database_type"] == "mysql":
        try:
            from database.mysql_create import (
                mysql_create_tables,
                mysql_create_database
            )
            mysql_create_database()
            mysql_create_tables()
        except Exception:
            die_failure(messages("en", "database_connection_failed"))
    elif nettacker_paths["database_type"] == "postgres":
        try:
            from database.postgres_create import postgres_create_database
            postgres_create_database()
        except Exception:
            die_failure(messages("en", "database_connection_failed"))
    else:
        die_failure(messages("en", "invalid_database"))
