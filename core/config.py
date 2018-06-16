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
        "info": ["port_scan"],
        "vulnerability": ["*_vuln"],
        "vuln": ["*_vuln"],
        "scan": ["*_scan"],
        "brute": ["*_brute"],
        "wp": ["wp_plugin_scan", "wp_theme_scan", "wp_timthumbs_scan", "wp_user_enum_scan",
               "wordpress_dos_cve_2018_6389_vuln", "wp_xmlrpc_bruteforce_vuln", "wp_xmlrpc_pingback_vuln"],
        "wordpress": ["wp_plugin_scan", "wp_theme_scan", "wp_timthumbs_scan", "wp_user_enum_scan",
                      "wordpress_dos_cve_2018_6389_vuln", "wp_xmlrpc_bruteforce_vuln", "wp_xmlrpc_pingback_vuln"],
        "joomla": ["joomla_template_scan", "joomla_user_enum_scan", "joomla_version_scan"]
    }


def _synonym_profile():
    return {
        "info": "information_gathering",
        "vuln": "vulnerability",
        "wp": "wordpress"
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
    }


def _database_config():
    """
    Database Config (could be modified by user)
    For sqlite database:
        fill the name of the DB as sqlite,
        DATABASE as the name of the db user wants
        other details can be left empty
    For mysql users:
        fill the name of the DB as mysql
        DATABASE as the name of the database you want to create
        USERNAME, PASSWORD, HOST and the PORT of the MySQL server need to be filled respectively

    Returns:
        a JSON with Database configuration
    """
    return {
        "DB": "sqlite",
        # "DB":"mysql",
        "DATABASE": _paths()["home_path"] + "/nettacker.db",  # Name of the database
        "USERNAME": "",
        "PASSWORD": "",
        "HOST": "",
        "PORT": ""
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
        "api_host": _api_config()["api_host"],
        "api_port": _api_config()["api_port"],
        "api_debug_mode": _api_config()["api_debug_mode"],
        "api_access_key": _api_config()["api_access_key"],
        "api_client_white_list": _api_config()["api_client_white_list"]["enabled"],
        "api_client_white_list_ips": _api_config()["api_client_white_list"]["ips"],
        "api_access_log": _api_config()["api_access_log"]["enabled"],
        "api_access_log_filename": _api_config()["api_access_log"]["filename"],
        "database_type": _database_config()["DB"],
        "database_name": _database_config()["DATABASE"],
        "database_username": _database_config()["USERNAME"],
        "database_password": _database_config()["PASSWORD"],
        "database_host": _database_config()["HOST"],
        "database_port": _database_config()["PORT"],
        "home_path": _paths()["home_path"],
        "tmp_path": _paths()["tmp_path"],
        "results_path": _paths()["results_path"]

    }
