#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import string
import os
import sys
from core.time import now
from core.utility import generate_random_token


def nettacker_paths():
    """
    home path for the framework (could be modify by user)

    Returns:
        a JSON contain the working, tmp and results path
    """
    return {
        "requirements_path": os.path.join(sys.path[0], 'requirements.txt'),
        "requirements_dev_path": os.path.join(sys.path[0], 'requirements-dev.txt'),
        "home_path": os.path.join(sys.path[0]),
        "data_path": os.path.join(sys.path[0], '.data'),
        "tmp_path": os.path.join(sys.path[0], '.data/tmp'),
        "results_path": os.path.join(sys.path[0], '.data/results'),
        "database_path": os.path.join(sys.path[0], '.data/nettacker.db'),
        "version_file": os.path.join(sys.path[0], 'version.txt'),
        "logo_file": os.path.join(sys.path[0], 'logo.txt'),
        "messages_path": os.path.join(sys.path[0], 'lib/messages'),
    }


def nettacker_api_config():
    """
    API Config (could be modify by user)

    Returns:
        a JSON with API configuration
    """
    return {  # OWASP Nettacker API Default Configuration
        "start_api_server": False,
        "api_hostname": "127.0.0.1",
        "api_port": 5000,
        "api_debug_mode": False,
        "api_access_key": generate_random_token(32),
        "api_client_whitelisted_ips": [],  # disabled
        # [
        #     "127.0.0.1",
        #     "10.0.0.0/24",
        #     "192.168.1.1-192.168.1.255"
        # ],
        "api_access_log": "nettacker.log",
    }


def nettacker_database_config():
    """
    Database Config (could be modified by user)
    For sqlite database:
        fill the name of the DB as sqlite,
        DATABASE as the name of the db user wants
        other details can be left empty
    For mysql users:
        fill the name of the DB as mysql
        DATABASE as the name of the database you want to create
        USERNAME, PASSWORD, HOST and the PORT of the MySQL server
        need to be filled respectively

    Returns:
        a JSON with Database configuration
    """
    return {
        "DB": "sqlite",
        # "DB":"mysql", "DB": "postgres"
        "DATABASE": nettacker_paths()["database_path"],
        # Name of the database
        "USERNAME": "",
        "PASSWORD": "",
        "HOST": "",
        "PORT": ""
    }


def nettacker_user_application_config():
    """
    core framework default config (could be modify by user)

    Returns:
        a JSON with all user default configurations
    """
    return {  # OWASP Nettacker Default Configuration
        "language": "en",
        "verbose_mode": False,
        "show_version": False,
        "output_file": "{0}/results_{1}_{2}.html".format(
            nettacker_paths()["results_path"],
            now(model="%Y_%m_%d_%H_%M_%S"),
            generate_random_token(10)
        ),
        "graph_name": "d3_tree_v2_graph",
        "show_help_menu": False,
        "targets": None,
        "targets_list": None,
        "selected_modules": None,
        "excluded_modules": None,
        "usernames": None,
        "usernames_list": None,
        "passwords": None,
        "passwords_list": None,
        "ports": None,
        "timeout_sec": 3.0,
        "time_sleep_between_requests": 0.0,
        "scan_ip_range": False,
        "scan_subdomains": False,
        "thread_per_host": 100,
        "parallel_host_scan": 5,
        "socks_proxy": None,
        "retries": 3,
        "ping_before_scan": False
    }


def nettacker_global_config():
    return {
        "nettacker_paths": nettacker_paths(),
        "nettacker_api_config": nettacker_api_config(),
        "nettacker_database_config": nettacker_database_config(),
        "nettacker_user_application_config": nettacker_user_application_config()
    }
