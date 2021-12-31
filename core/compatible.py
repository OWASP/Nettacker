#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
from .die import die_failure
from core import color


def version_info():
    """
    version information of the framework

    Returns:
        an array of version and code name
    """
    import config
    return open(config.nettacker_paths()['version_file']).read().split()


def logo():
    """
    OWASP Nettacker Logo
    """
    from core.alert import write_to_api_console
    from core import color
    from core.color import reset_color
    from config import nettacker_paths
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


# noinspection PyBroadException
def check_dependencies():
    """
    check requirements before execution.

    Returns:
        object: scan unique id (string)
    """
    if python_version() == 2:
        sys.exit(
            color.color("red") +
            "[X] " +
            color.color("yellow") +
            "Python2 is No longer supported!" +
            color.color("reset")
        )

    # check os compatibility
    from config import (nettacker_paths,
                        nettacker_global_config)
    from database.connector import RedisConnector
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
                    color.color("red") + "[X] " + color.color("yellow") + "pip3 install -r requirements.txt ---> " +
                    module_name.split('#')[0].strip() + " not installed!" + color.color("reset")
                )
    logo()

    from core.alert import messages
    if not ('linux' in os_name() or 'darwin' in os_name()):
        die_failure(messages("error_platform"))

    if not os.path.exists(nettacker_paths()["home_path"]):
        try:
            os.mkdir(nettacker_paths()["home_path"])
            os.mkdir(nettacker_paths()["tmp_path"])
            os.mkdir(nettacker_paths()["results_path"])
        except Exception:
            die_failure("cannot access the directory {0}".format(
                nettacker_paths()["home_path"])
            )
    if not os.path.exists(nettacker_paths()["tmp_path"]):
        try:
            os.mkdir(nettacker_paths()["tmp_path"])
        except Exception:
            die_failure("cannot access the directory {0}".format(
                nettacker_paths()["results_path"])
            )
    if not os.path.exists(nettacker_paths()["results_path"]):
        try:
            os.mkdir(nettacker_paths()["results_path"])
        except Exception:
            die_failure("cannot access the directory {0}".format(
                nettacker_paths()["results_path"])
            )
    redis = RedisConnector()
    try:
        redis.read('*', '*')
    except Exception:
        die_failure(messages("cannot_connect_to_redis"))
    from core.utility import generate_random_token
    scan_unique_id = generate_random_token(32)

    if redis.read("nettacker_engines", ".") is None:
        redis.write(
            'nettacker_engines',
            '.',
            {
                redis.normalize_key_name(
                    nettacker_global_config()["nettacker_engine_identifier"]
                ): {
                    "scans": {
                        redis.normalize_key_name(
                            scan_unique_id
                        ): {
                            "options": {},
                            "expand_targets": {},
                            "processes": {}
                        }
                    }
                }
            }
        )
        redis_scan_engine_path = "." + redis.normalize_key_name(
            nettacker_global_config()["nettacker_engine_identifier"]
        ) + ".scans." + redis.normalize_key_name(
            scan_unique_id
        )
    else:
        redis_scan_engine_path = '.' + redis.normalize_key_name(
            nettacker_global_config()["nettacker_engine_identifier"]
        )
        redis.write(
            'nettacker_engines',
            redis_scan_engine_path,
            {
                "scans": {}
            },
            nx=True
        )
        redis_scan_engine_path += ".scans." + redis.normalize_key_name(
            scan_unique_id
        )
        redis.write(
            'nettacker_engines',
            redis_scan_engine_path,
            {
                "options": {},
                "expand_targets": {},
                "processes": {}
            }
        )
    if redis.read("nettacker_events", ".") is None:
        redis.write(
            "nettacker_events",
            ".",
            {}
        )

    if redis.read("nettacker_temporary_events", ".") is None:
        redis.write(
            "nettacker_temporary_events",
            ".",
            {}
        )
    if redis.read("nettacker_scans", ".") is None:
        redis.write(
            "nettacker_scans",
            ".",
            {}
        )
    return scan_unique_id
