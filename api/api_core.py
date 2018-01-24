#!/usr/bin/env python
# -*- coding: utf-8 -*-

from core.load_modules import load_all_modules
from core.load_modules import load_all_graphs
from core.alert import messages
from core.alert import warn


def __structure(status="", msg=""):
    return {
        "status": status,
        "msg": msg
    }


def __get_value(flask_request, _key):
    try:
        key = flask_request.args[_key]
    except:
        try:
            key = flask_request.form[_key]
        except:
            key = None
    return key


def __remove_non_api_keys(config):
    non_api_keys = ["start_api", "api_host", "api_port", "api_debug_mode", "api_access_key", "api_client_white_list",
                    "api_client_white_list_ips", "api_access_log", "api_access_log", "api_access_log_filename",
                    "show_version", "check_update", "help_menu_flag", "targets_list", "users_list", "passwds_list",
                    "method_args_list", "startup_check_for_update", "wizard_mode", "exclude_method"]
    new_config = {}
    for key in config:
        if key not in non_api_keys:
            new_config[key] = config[key]
    return new_config


def __rules(config, defaults, language):
    
    return config
