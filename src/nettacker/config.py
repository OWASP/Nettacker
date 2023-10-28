#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from pathlib import Path
from nettacker.core.time import now
from nettacker.core.utility import generate_random_token


CWD = Path.cwd()
PACKAGE_PATH = Path(__file__).parent


def nettacker_paths():
    """
    home path for the framework (could be modify by user)

    Returns:
        a JSON contain the working, tmp and results path
    """

    return {
        "home_path": CWD,
        "data_path": CWD / ".data",
        "tmp_path": CWD / ".data/tmp",
        "results_path": CWD / ".data/results",
        "database_path": CWD / ".data/nettacker.db",
        "release_name_file": PACKAGE_PATH / "release_name.txt",
        "logo_file": PACKAGE_PATH / "logo.txt",
        "graph_path": PACKAGE_PATH / "lib/graph",
        "messages_path": PACKAGE_PATH / "lib/messages",
        "modules_path": PACKAGE_PATH / "modules",
        "web_browser_user_agents": PACKAGE_PATH
        / "lib/payloads/User-Agents/web_browsers_user_agents.txt",
        "web_static_files_path": PACKAGE_PATH / "web/static",
        "payloads_path": PACKAGE_PATH / "lib/payloads",
        "module_protocols_path": PACKAGE_PATH / "core/module_protocols",
    }


def nettacker_api_config():
    """
    API Config (could be modify by user)

    Returns:
        a JSON with API configuration
    """
    return {  # OWASP Nettacker API Default Configuration
        "start_api_server": False,
        "api_hostname": "0.0.0.0"
        if os.environ.get("docker_env") == "true"
        else "nettacker-api.z3r0d4y.com",
        "api_port": 5000,
        "api_debug_mode": False,
        "api_access_key": generate_random_token(32),
        "api_client_whitelisted_ips": [],  # disabled - to enable please put an array with list of ips/cidr/ranges
        # [
        #     "127.0.0.1",
        #     "10.0.0.0/24",
        #     "192.168.1.1-192.168.1.255"
        # ],
        "api_access_log": CWD / ".data/nettacker.log",
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
        "PORT": "",
    }


def nettacker_user_application_config():
    """
    core framework default config (could be modify by user)

    Returns:
        a JSON with all user default configurations
    """
    from nettacker.core.compatible import version_info

    return {  # OWASP Nettacker Default Configuration
        "language": "en",
        "verbose_mode": False,
        "verbose_event": False,
        "show_version": False,
        "report_path_filename": "{results_path}/results_{date_time}_{random_chars}.html".format(
            results_path=nettacker_paths()["results_path"],
            date_time=now(model="%Y_%m_%d_%H_%M_%S"),
            random_chars=generate_random_token(10),
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
        "timeout": 3.0,
        "time_sleep_between_requests": 0.0,
        "scan_ip_range": False,
        "scan_subdomains": False,
        "skip_service_discovery": False,
        "thread_per_host": 100,
        "parallel_module_scan": 1,
        "socks_proxy": None,
        "retries": 1,
        "ping_before_scan": False,
        "profiles": None,
        "set_hardware_usage": "maximum",  # low, normal, high, maximum
        "user_agent": "Nettacker {version_number} {version_code}".format(
            version_number=version_info()[0], version_code=version_info()[1]
        ),
        "show_all_modules": False,
        "show_all_profiles": False,
        "modules_extra_args": None,
    }


def nettacker_global_config():
    return {
        "nettacker_paths": nettacker_paths(),
        "nettacker_api_config": nettacker_api_config(),
        "nettacker_database_config": nettacker_database_config(),
        "nettacker_user_application_config": nettacker_user_application_config(),
    }
