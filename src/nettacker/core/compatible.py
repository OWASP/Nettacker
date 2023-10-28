#!/usr/bin/env python3

import os
import sys

from nettacker.core import color
from nettacker.core.die import die_failure


def version_info():
    """
    version information of the framework

    Returns:
        an array of version and code name
    """
    import importlib.metadata

    from nettacker.config import nettacker_paths

    return (
        importlib.metadata.version("nettacker"),
        open(nettacker_paths()["release_name_file"]).read().strip(),
    )


def logo():
    """
    OWASP Nettacker Logo
    """
    from nettacker.config import nettacker_paths
    from nettacker.core import color
    from nettacker.core.alert import write_to_api_console
    from nettacker.core.color import reset_color

    write_to_api_console(
        open(nettacker_paths()["logo_file"])
        .read()
        .format(
            version_info()[0],
            version_info()[1],
            color.color("red"),
            color.color("reset"),
            color.color("yellow"),
            color.color("reset"),
            color.color("cyan"),
            color.color("reset"),
            color.color("cyan"),
            color.color("reset"),
            color.color("cyan"),
            color.color("reset"),
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
        sys.exit(
            color.color("red")
            + "[X] "
            + color.color("yellow")
            + "Python2 is No longer supported!"
            + color.color("reset")
        )

    # # check os compatibility
    from nettacker.config import nettacker_database_config, nettacker_paths

    logo()

    from nettacker.core.alert import messages

    if not ("linux" in os_name() or "darwin" in os_name()):
        die_failure(messages("error_platform"))

    if not os.path.exists(nettacker_paths()["home_path"]):
        try:
            os.mkdir(nettacker_paths()["home_path"])
            os.mkdir(nettacker_paths()["tmp_path"])
            os.mkdir(nettacker_paths()["results_path"])
        except Exception:
            die_failure("cannot access the directory {0}".format(nettacker_paths()["home_path"]))
    if not os.path.exists(nettacker_paths()["tmp_path"]):
        try:
            os.mkdir(nettacker_paths()["tmp_path"])
        except Exception:
            die_failure(
                "cannot access the directory {0}".format(nettacker_paths()["results_path"])
            )
    if not os.path.exists(nettacker_paths()["results_path"]):
        try:
            os.mkdir(nettacker_paths()["results_path"])
        except Exception:
            die_failure(
                "cannot access the directory {0}".format(nettacker_paths()["results_path"])
            )

    if nettacker_database_config()["DB"] == "sqlite":
        try:
            if not os.path.isfile(nettacker_paths()["database_path"]):
                from nettacker.database.sqlite_create import sqlite_create_tables

                sqlite_create_tables()
        except Exception:
            die_failure("cannot access the directory {0}".format(nettacker_paths()["home_path"]))
    elif nettacker_database_config()["DB"] == "mysql":
        try:
            from nettacker.database.mysql_create import mysql_create_database, mysql_create_tables

            mysql_create_database()
            mysql_create_tables()
        except Exception:
            die_failure(messages("database_connection_failed"))
    elif nettacker_database_config()["DB"] == "postgres":
        try:
            from nettacker.database.postgres_create import postgres_create_database

            postgres_create_database()
        except Exception:
            die_failure(messages("database_connection_failed"))
    else:
        die_failure(messages("invalid_database"))
