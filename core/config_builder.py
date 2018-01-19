#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random
import string
from core._time import now


def default_profiles():
    return {
        "information_gathering": ["tcp_connect_port_scan"],
        "vulnerabilities": ["heartbleed_vuln"]
    }


def _api_default_config():
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
            "filename": "nettacker_api_access_log"
        }
    }


def _core_default_config():
    return {
        "language": "en",
        "verbose_level": 0,
        "show_version": False,
        "check_update": False,
        "log_in_file": "results/results_{0}_{1}.html".format(now(model="%Y_%m_%d_%H_%M_%S"),
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
        "thread_number": 10,
        "thread_number_host": 10,
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
        "api_access_log_filename": _api_default_config()["api_access_log"]["filename"]
    }


def _builder(defaults, keys):
    for key in keys:
        try:
            defaults[key]
        except:
            defaults[key] = keys[key]
    return defaults
