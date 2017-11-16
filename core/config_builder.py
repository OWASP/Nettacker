#!/usr/bin/env python
# -*- coding: utf-8 -*-


def all_config_keys():
    return {
        "language": "en",
        "verbose_level": 0,
        "show_version": False,
        "check_update": False,
        "log_in_file": "results.html",
        "graph_flag": "d3_tree_v1_graph",
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
        "proxies": None,
        "proxies_file": None,
        "retries": 3,
        "ping_flag": False,
        "methods_args": None,
        "method_args_list": False,
        "startup_check_for_update": True
    }

def _builder(default_config):
    config_keys = all_config_keys()
    for key in config_keys:
        try:
            default_config[key]
        except:
            default_config[key] = config_keys[key]
    return default_config
