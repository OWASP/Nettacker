#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random
import string
import os
import inspect
import api
from core._time import now


def _paths():
    """
    home path for the framework (could be modify by user)

    Returns:
        a JSON contain the working, tmp and results path
    """
    return {
        "home_path": os.path.expanduser('~/.owasp-nettacker'),
        "tmp_path": os.path.expanduser('~/.owasp-nettacker/tmp'),
        "results_path": os.path.expanduser('~/.owasp-nettacker/results')
    }


def _profiles():
    """
    a shortcut and users profile to run customize scans (could be modify by user)

    Returns:
        a JSON contains profile names and module names for each
    """
    return {
        "information_gathering": ["port_scan"],
        "vulnerability": ["*_vuln"],
        "scan": ["*_scan"],
        "brute": ["*_brute"]
    }


def _api_config():
    """
    API Config (could be modify by user)

    Returns:
        a JSON with API configuration
    """
    return {  # OWASP Nettacker API Default Configuration
        "api_host": "127.0.0.1",
        "api_port": 5000,
        "api_debug_mode": False,
        "api_access_key": "".join(random.choice("0123456789abcdef") for x in range(32)),
        "api_client_white_list": {
            "enabled": False,
            "ips": ["127.0.0.1", "10.0.0.0/24", "192.168.1.1-192.168.1.255"]
        },
        "api_access_log": {
            "enabled": False,
            "filename": "nettacker_api_access.log"
        },
        "api_db_name": _paths()["home_path"] + "/database.sqlite3"
    }


def _core_config():
    """
    core framework default config (could be modify by user)

    Returns:
        a JSON with all user default configurations
    """
    return {  # OWASP Nettacker Default Configuration
        "language": "en",
        "verbose_level": 0,
        "show_version": False,
        "check_update": False,
        "log_in_file": "{0}/results_{1}_{2}.html".format(_paths()["results_path"], now(model="%Y_%m_%d_%H_%M_%S"),
                                                         "".join(random.choice(string.ascii_lowercase) for x in
                                                                 range(10))),
        "graph_flag": "d3_tree_v2_graph",
        "help_menu_flag": False,
        "targets": None,
        "targets_list": None,
        "scan_method": None,
        "exclude_method": None,
        "users": None,
        "users_list": None,
        "passwds": None,
        "passwds_list": None,
        "ports": None,
        "timeout_sec": 3.0,
        "time_sleep": 0.0,
        "check_ranges": False,
        "check_subdomains": False,
        "thread_number": 100,
        "thread_number_host": 30,
        "socks_proxy": None,
        "retries": 3,
        "ping_flag": False,
        "methods_args": None,
        "method_args_list": False,
        "startup_check_for_update": True,
        "wizard_mode": False,
        "profile": None,
        "start_api": False,
        "api_host": _api_config()["api_host"],
        "api_port": _api_config()["api_port"],
        "api_debug_mode": _api_config()["api_debug_mode"],
        "api_access_key": _api_config()["api_access_key"],
        "api_client_white_list": _api_config()["api_client_white_list"]["enabled"],
        "api_client_white_list_ips": _api_config()["api_client_white_list"]["ips"],
        "api_access_log": _api_config()["api_access_log"]["enabled"],
        "api_access_log_filename": _api_config()["api_access_log"]["filename"],
        "api_db_name": _api_config()["api_db_name"],
        "home_path": _paths()["home_path"],
        "tmp_path": _paths()["tmp_path"],
        "results_path": _paths()["results_path"]

    }
