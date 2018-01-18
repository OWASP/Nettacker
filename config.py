#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random
import string
from core._time import now


def _profiles():
    return {
        "information_gathering": ["tcp_connect_port_scan"],
        "vulnerabilities": ["heartbleed_vuln"]
    }


def _core_config():
    return {  # OWASP Nettacker Default Configuration
        "language": "en",
        "verbose_level": 0,
        "show_version": False,
        "check_update": False,
        "log_in_file": "results/results_{0}_{1}.html".format(now(model="%Y_%m_%d_%H_%M_%S"),
                                                             ''.join(random.choice(string.ascii_lowercase) for x in
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
        "profile": None
    }


def _api_config():
    return {
        "api_host": "127.0.0.1",
        "api_port": 5000,
        "api_debug_mode": False,
        "api_access_key": "random_private_access_key",
        "api_client_white_list": {
            "enabled": False,
            "api_client_white_list_ip": ["127.0.0.1", "10.0.0.1"]
        },
        "api_access_log": {
            "enabled": False,
            "filename": "nettacker_api_access_log"
        }
    }
