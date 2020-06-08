#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random
import string
import os
import inspect
import api
from core._time import now


def default_paths():
    """
    home path for the framework

    Returns:
        a JSON contain the working, tmp and results path
    """
    return {
        "home_path": os.path.expanduser('~/.owasp-nettacker'),
        "tmp_path": os.path.expanduser('~/.owasp-nettacker/tmp'),
        "results_path": os.path.expanduser('~/.owasp-nettacker/results')
    }


def default_profiles():
    """
    a shortcut and users profile to run customize scans

    Returns:
        a JSON contains profile names and module names for each
    """
    return {
        "information_gathering": ["port_scan"],
        "vulnerability": ["*_vuln"],
        "scan": ["*_scan"],
        "brute": ["*_brute"]
    }


def _api_default_config():
    """
    API Config

    Returns:
        a JSON with API configuration
    """
    return {
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
    }


def _database_default_config():
    """
        Default database Config

        Returns:
            a JSON with Database configuration
        """
    return {
        "DB": "sqlite",
        "DATABASE": default_paths()["home_path"] + "/nettacker.db",
        "USERNAME": "",
        "PASSWORD": "",
        "HOST": "",
        "PORT": ""
    }


def _core_default_config():
    """
    core framework default config

    Returns:
        a JSON with all user default configurations
    """
    return {
        "language": "en",
        "verbose_level": 0,
        "show_version": False,
        "check_update": False,
        "log_in_file": "{0}/results_{1}_{2}.html".format(default_paths()["results_path"],
                                                         now(model="%Y_%m_%d_%H_%M_%S"),
                                                         "".join(random.choice(string.ascii_lowercase) for x in
                                                                 range(10))),
        "graph_flag": "d3_tree_v2_graph",
        "help_menu_flag": False,
        "targets": None,
        "targets_list": None,
        "scan_method": "all",
        "exclude_method": None,
        "users": None,
        "users_list": None,
        "passwds": None,
        "passwds_list": None,
        "ports": None,
        "timeout_sec": 2.0,
        "time_sleep": 0.0,
        "check_ranges": False,
        "check_subdomains": False,
        "thread_number": 100,
        "thread_number_host": 5,
        "socks_proxy": None,
        "retries": 3,
        "ping_flag": False,
        "methods_args": None,
        "method_args_list": False,
        "startup_check_for_update": True,
        "wizard_mode": False,
        "profile": None,
        "start_api": False,
        "api_host": _api_default_config()["api_host"],
        "api_port": _api_default_config()["api_port"],
        "api_debug_mode": _api_default_config()["api_debug_mode"],
        "api_access_key": _api_default_config()["api_access_key"],
        "api_client_white_list": _api_default_config()["api_client_white_list"]["enabled"],
        "api_client_white_list_ips": _api_default_config()["api_client_white_list"]["ips"],
        "api_access_log": _api_default_config()["api_access_log"]["enabled"],
        "api_access_log_filename": _api_default_config()["api_access_log"]["filename"],
        "database_type": _database_default_config()["DB"],
        "database_name": _database_default_config()["DATABASE"],
        "database_username": _database_default_config()["USERNAME"],
        "database_password": _database_default_config()["PASSWORD"],
        "database_host": _database_default_config()["HOST"],
        "database_port": _database_default_config()["PORT"],
        "home_path": default_paths()["home_path"],
        "tmp_path": default_paths()["tmp_path"],
        "results_path": default_paths()["results_path"]
    }


def _builder(defaults, keys):
    """

    Args:
        defaults:
        keys:

    Returns:

    """
    for key in keys:
        try:
            defaults[key]
        except:
            defaults[key] = keys[key]
    return defaults
