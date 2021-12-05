#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import json

from core.alert import write
from core.alert import warn
from core.alert import info
from core.alert import messages
from core.color import color
from core.compatible import version_info
from config import nettacker_global_config
from core.load_modules import load_all_languages
from core.utility import (application_language,
                          select_maximum_cpu_core)
from core.die import die_success
from core.die import die_failure
from core.color import reset_color
from core.load_modules import load_all_modules
from core.load_modules import load_all_graphs
from core.load_modules import load_all_profiles


def load_all_args():
    """
    create the ARGS and help menu

    Returns:
        the parser, the ARGS
    """

    nettacker_global_configuration = nettacker_global_config()

    # Language Options
    language = application_language()
    languages_list = load_all_languages()
    if language not in languages_list:
        die_failure(
            "Please select one of these languages {0}".format(
                languages_list
            )
        )

    reset_color()
    # Start Parser
    parser = argparse.ArgumentParser(prog="Nettacker", add_help=False)

    # Engine Options
    engineOpt = parser.add_argument_group(
        messages("engine"), messages("engine_input")
    )
    engineOpt.add_argument(
        "-L",
        "--language",
        action="store",
        dest="language",
        default=nettacker_global_configuration['nettacker_user_application_config']["language"],
        help=messages("select_language").format(languages_list),
    )
    engineOpt.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        dest="verbose_mode",
        default=nettacker_global_configuration['nettacker_user_application_config']['verbose_mode'],
        help=messages("verbose_mode"),
    )
    engineOpt.add_argument(
        "--verbose-event",
        action="store_true",
        dest="verbose_event",
        default=nettacker_global_configuration['nettacker_user_application_config']['verbose_event'],
        help=messages("verbose_event"),
    )
    engineOpt.add_argument(
        "-V",
        "--version",
        action="store_true",
        default=nettacker_global_configuration['nettacker_user_application_config']['show_version'],
        dest="show_version",
        help=messages("software_version"),
    )
    engineOpt.add_argument(
        "-o",
        "--output",
        action="store",
        default=nettacker_global_configuration['nettacker_user_application_config']['report_path_filename'],
        dest="report_path_filename",
        help=messages("save_logs"),
    )
    engineOpt.add_argument(
        "--graph",
        action="store",
        default=nettacker_global_configuration['nettacker_user_application_config']["graph_name"],
        dest="graph_name",
        help=messages("available_graph").format(load_all_graphs()),
    )
    engineOpt.add_argument(
        "-h",
        "--help",
        action="store_true",
        default=nettacker_global_configuration['nettacker_user_application_config']["show_help_menu"],
        dest="show_help_menu",
        help=messages("help_menu"),
    )

    # Target Options
    target = parser.add_argument_group(
        messages("target"), messages("target_input")
    )
    target.add_argument(
        "-i",
        "--targets",
        action="store",
        dest="targets",
        default=nettacker_global_configuration['nettacker_user_application_config']["targets"],
        help=messages("target_list"),
    )
    target.add_argument(
        "-l",
        "--targets-list",
        action="store",
        dest="targets_list",
        default=nettacker_global_configuration['nettacker_user_application_config']["targets_list"],
        help=messages("read_target"),
    )

    # Exclude Module Name
    exclude_modules = list(load_all_modules(limit=10).keys())
    exclude_modules.remove("all")

    # Methods Options
    modules = parser.add_argument_group(
        messages("Method"), messages("scan_method_options")
    )
    modules.add_argument(
        "-m",
        "--modules",
        action="store",
        dest="selected_modules",
        default=nettacker_global_configuration['nettacker_user_application_config']["selected_modules"],
        help=messages("choose_scan_method").format(list(load_all_modules(limit=10).keys())),
    )
    modules.add_argument(
        "--modules-extra-args",
        action="store",
        dest="modules_extra_args",
        default=nettacker_global_configuration['nettacker_user_application_config']['modules_extra_args'],
        help=messages("modules_extra_args_help")
    )
    modules.add_argument(
        "--show-all-modules",
        action="store_true",
        dest="show_all_modules",
        default=nettacker_global_configuration['nettacker_user_application_config']["show_all_modules"],
        help=messages("show_all_modules"),
    )
    modules.add_argument(
        "--profile",
        action="store",
        default=nettacker_global_configuration['nettacker_user_application_config']["profiles"],
        dest="profiles",
        help=messages("select_profile").format(list(load_all_profiles(limit=10).keys())),
    )
    modules.add_argument(
        "--show-all-profiles",
        action="store_true",
        dest="show_all_profiles",
        default=nettacker_global_configuration['nettacker_user_application_config']["show_all_profiles"],
        help=messages("show_all_profiles"),
    )
    modules.add_argument(
        "-x",
        "--exclude-modules",
        action="store",
        dest="excluded_modules",
        default=nettacker_global_configuration['nettacker_user_application_config']["excluded_modules"],
        help=messages("exclude_scan_method").format(exclude_modules),
    )
    modules.add_argument(
        "-u",
        "--usernames",
        action="store",
        dest="usernames",
        default=nettacker_global_configuration['nettacker_user_application_config']["usernames"],
        help=messages("username_list"),
    )
    modules.add_argument(
        "-U",
        "--users-list",
        action="store",
        dest="usernames_list",
        default=nettacker_global_configuration['nettacker_user_application_config']["usernames_list"],
        help=messages("username_from_file"),
    )
    modules.add_argument(
        "-p",
        "--passwords",
        action="store",
        dest="passwords",
        default=nettacker_global_configuration['nettacker_user_application_config']["passwords"],
        help=messages("password_seperator"),
    )
    modules.add_argument(
        "-P",
        "--passwords-list",
        action="store",
        dest="passwords_list",
        default=nettacker_global_configuration['nettacker_user_application_config']["passwords_list"],
        help=messages("read_passwords"),
    )
    modules.add_argument(
        "-g",
        "--ports",
        action="store",
        dest="ports",
        default=nettacker_global_configuration['nettacker_user_application_config']["ports"],
        help=messages("port_seperator"),
    )
    modules.add_argument(
        "--user-agent",
        action="store",
        dest="user_agent",
        default=nettacker_global_configuration['nettacker_user_application_config']["user_agent"],
        help=messages("select_user_agent"),
    )
    modules.add_argument(
        "-T",
        "--timeout",
        action="store",
        dest="timeout",
        default=nettacker_global_configuration['nettacker_user_application_config']["timeout"],
        type=float,
        help=messages("read_passwords"),
    )
    modules.add_argument(
        "-w",
        "--time-sleep-between-requests",
        action="store",
        dest="time_sleep_between_requests",
        default=nettacker_global_configuration['nettacker_user_application_config']["time_sleep_between_requests"],
        type=float,
        help=messages("time_to_sleep"),
    )
    modules.add_argument(
        "-r",
        "--range",
        action="store_true",
        default=nettacker_global_configuration['nettacker_user_application_config']["scan_ip_range"],
        dest="scan_ip_range",
        help=messages("range"),
    )
    modules.add_argument(
        "-s",
        "--sub-domains",
        action="store_true",
        default=nettacker_global_configuration['nettacker_user_application_config']["scan_subdomains"],
        dest="scan_subdomains",
        help=messages("subdomains"),
    )
    modules.add_argument(
        "--skip-service-discovery",
        action="store_true",
        default=nettacker_global_configuration['nettacker_user_application_config']["skip_service_discovery"],
        dest="skip_service_discovery",
        help=messages("skip_service_discovery")
    )
    modules.add_argument(
        "-t",
        "--thread-per-host",
        action="store",
        default=nettacker_global_configuration['nettacker_user_application_config']["thread_per_host"],
        type=int,
        dest="thread_per_host",
        help=messages("thread_number_connections"),
    )
    modules.add_argument(
        "-M",
        "--parallel-module-scan",
        action="store",
        default=nettacker_global_configuration['nettacker_user_application_config']["parallel_module_scan"],
        type=int,
        dest="parallel_module_scan",
        help=messages("thread_number_modules"),
    )
    modules.add_argument(
        "--set-hardware-usage",
        action="store",
        dest="set_hardware_usage",
        default=nettacker_global_configuration['nettacker_user_application_config']['set_hardware_usage'],
        help=messages("set_hardware_usage")
    )
    modules.add_argument(
        "-R",
        "--socks-proxy",
        action="store",
        dest="socks_proxy",
        default=nettacker_global_configuration['nettacker_user_application_config']["socks_proxy"],
        help=messages("outgoing_proxy"),
    )
    modules.add_argument(
        "--retries",
        action="store",
        dest="retries",
        type=int,
        default=nettacker_global_configuration['nettacker_user_application_config']["retries"],
        help=messages("connection_retries"),
    )
    modules.add_argument(
        "--ping-before-scan",
        action="store_true",
        dest="ping_before_scan",
        default=nettacker_global_configuration['nettacker_user_application_config']["ping_before_scan"],
        help=messages("ping_before_scan"),
    )
    # API Options
    api = parser.add_argument_group(
        messages("API"),
        messages("API_options")
    )
    api.add_argument(
        "--start-api",
        action="store_true",
        dest="start_api_server",
        default=nettacker_global_configuration['nettacker_api_config']["start_api_server"],
        help=messages("start_api_server")
    )
    api.add_argument(
        "--api-host",
        action="store",
        dest="api_hostname",
        default=nettacker_global_configuration['nettacker_api_config']["api_hostname"],
        help=messages("API_host")
    )
    api.add_argument(
        "--api-port",
        action="store",
        dest="api_port",
        default=nettacker_global_configuration['nettacker_api_config']["api_port"],
        help=messages("API_port")
    )
    api.add_argument(
        "--api-debug-mode",
        action="store_true",
        dest="api_debug_mode",
        default=nettacker_global_configuration['nettacker_api_config']["api_debug_mode"],
        help=messages("API_debug")
    )
    api.add_argument(
        "--api-access-key",
        action="store",
        dest="api_access_key",
        default=nettacker_global_configuration['nettacker_api_config']["api_access_key"],
        help=messages("API_access_key")
    )
    api.add_argument(
        "--api-client-whitelisted-ips",
        action="store",
        dest="api_client_whitelisted_ips",
        default=nettacker_global_configuration['nettacker_api_config']["api_client_whitelisted_ips"],
        help=messages("define_whie_list")
    )
    api.add_argument(
        "--api-access-log",
        action="store",
        dest="api_access_log",
        default=nettacker_global_configuration['nettacker_api_config']["api_access_log"],
        help=messages("API_access_log_file")
    )
    api.add_argument(
        "--api-cert",
        action="store",
        dest="api_cert",
        help=messages("API_cert")
    )
    api.add_argument(
        "--api-cert-key",
        action="store",
        dest="api_cert_key",
        help=messages("API_cert_key")
    )
    # Return Options
    return parser


def check_all_required(parser, api_forms=None):
    """
    check all rules and requirements for ARGS

    Args:
        parser: parser from argparse
        api_forms: values from API

    Returns:
        all ARGS with applied rules
    """
    # Checking Requirements
    options = parser.parse_args() if not api_forms else api_forms
    modules_list = load_all_modules(full_details=True)
    profiles_list = load_all_profiles()

    # Check Help Menu
    if options.show_help_menu:
        parser.print_help()
        write("\n\n")
        write(messages("license"))
        die_success()

    # Check version
    if options.show_version:
        info(
            messages("current_version").format(
                color("yellow"),
                version_info()[0],
                color("reset"),
                color("cyan"),
                version_info()[1],
                color("reset"),
                color("green"),
            )
        )
        die_success()
    if options.show_all_modules:
        messages("loading_modules")
        for module in modules_list:
            info(
                messages("module_profile_full_information").format(
                    color('cyan'),
                    module,
                    color('green'),
                    ", ".join(
                        [
                            "{key}: {value}".format(
                                key=key, value=modules_list[module][key]
                            ) for key in modules_list[module]
                        ]
                    )
                )
            )
        die_success()
    if options.show_all_profiles:
        messages("loading_profiles")
        for profile in profiles_list:
            info(
                messages("module_profile_full_information").format(
                    color('cyan'),
                    profile,
                    color('green'),
                    ", ".join(profiles_list[profile])
                )
            )
        die_success()
    # API mode
    if options.start_api_server:
        if '--start-api' in sys.argv and api_forms:
            die_failure(messages("cannot_run_api_server"))
        from api.engine import start_api_server
        if options.api_client_whitelisted_ips:
            if type(options.api_client_whitelisted_ips) == str:
                options.api_client_whitelisted_ips = options.api_client_whitelisted_ips.split(',')
                whielisted_ips = []
                for ip in options.api_client_whitelisted_ips:
                    from core.ip import (is_single_ipv4,
                                         is_single_ipv6,
                                         is_ipv4_cidr,
                                         is_ipv6_range,
                                         is_ipv6_cidr,
                                         is_ipv4_range,
                                         generate_ip_range)
                    if is_single_ipv4(ip) or is_single_ipv6(ip):
                        whielisted_ips.append(ip)
                    elif is_ipv4_range(ip) or is_ipv6_range(ip) or is_ipv4_cidr(ip) or is_ipv6_cidr(ip):
                        whielisted_ips += generate_ip_range(ip)
                options.api_client_whitelisted_ips = whielisted_ips
        start_api_server(options)

    # Check the target(s)
    if not (options.targets or options.targets_list) or (options.targets and options.targets_list):
        parser.print_help()
        write("\n")
        die_failure(messages("error_target"))
    if options.targets:
        options.targets = list(set(options.targets.split(",")))
    if options.targets_list:
        try:
            options.targets = list(set(open(options.targets_list, "rb").read().decode().split()))
        except Exception:
            die_failure(
                messages("error_target_file").format(
                    options.targets_list
                )
            )

    # check for modules
    if not (options.selected_modules or options.profiles):
        die_failure(messages("scan_method_select"))
    if options.selected_modules:
        if options.selected_modules == 'all':
            options.selected_modules = list(set(modules_list.keys()))
            options.selected_modules.remove('all')
        else:
            options.selected_modules = list(set(options.selected_modules.split(',')))
        for module_name in options.selected_modules:
            if module_name not in modules_list:
                die_failure(
                    messages("scan_module_not_found").format(
                        module_name
                    )
                )
    if options.profiles:
        if not options.selected_modules:
            options.selected_modules = []
        if options.profiles == 'all':
            options.selected_modules = list(set(modules_list.keys()))
            options.selected_modules.remove('all')
        else:
            options.profiles = list(set(options.profiles.split(',')))
            for profile in options.profiles:
                if profile not in profiles_list:
                    die_failure(
                        messages("profile_404").format(
                            profile
                        )
                    )
                for module_name in profiles_list[profile]:
                    if module_name not in options.selected_modules:
                        options.selected_modules.append(module_name)
    # threading & processing
    if options.set_hardware_usage not in ['low', 'normal', 'high', 'maximum']:
        die_failure(
            messages("wrong_hardware_usage")
        )
    options.set_hardware_usage = select_maximum_cpu_core(options.set_hardware_usage)

    options.thread_per_host = int(options.thread_per_host)
    if not options.thread_per_host >= 1:
        options.thread_per_host = 1
    options.parallel_module_scan = int(options.parallel_module_scan)
    if not options.parallel_module_scan >= 1:
        options.parallel_module_scan = 1

    # Check for excluding modules
    if options.excluded_modules:
        options.excluded_modules = options.excluded_modules.split(",")
        if 'all' in options.excluded_modules:
            die_failure(messages("error_exclude_all"))
        for excluded_module in options.excluded_modules:
            if excluded_module in options.selected_modules:
                del options.selected_modules[excluded_module]
    # Check port(s)
    if options.ports:
        tmp_ports = []
        for port in options.ports.split(","):
            try:
                if "-" in port:
                    for port_number in range(int(port.split('-')[0]), int(port.split('-')[1]) + 1):
                        if port_number not in tmp_ports:
                            tmp_ports.append(port_number)
                else:
                    if int(port) not in tmp_ports:
                        tmp_ports.append(int(port))
            except Exception:
                die_failure(messages("ports_int"))
        options.ports = tmp_ports

    if options.user_agent == 'random_user_agent':
        options.user_agents = open(
            nettacker_global_config()['nettacker_paths']['web_browser_user_agents']
        ).read().split('\n')

    # Check user list
    if options.usernames:
        options.usernames = list(set(options.usernames.split(",")))
    elif options.usernames_list:
        try:
            options.usernames = list(set(open(options.usernames_list).read().split("\n")))
        except Exception:
            die_failure(
                messages("error_username").format(options.usernames_list)
            )
    # Check password list
    if options.passwords:
        options.passwords = list(set(options.passwords.split(",")))
    elif options.passwords_list:
        try:
            options.passwords = list(set(open(options.passwords_list).read().split("\n")))
        except Exception:
            die_failure(
                messages("error_passwords").format(options.passwords_list)
            )
    # Check output file
    try:
        temp_file = open(options.report_path_filename, "w")
        temp_file.close()
    except Exception:
        die_failure(
            messages("file_write_error").format(options.report_path_filename)
        )
    # Check Graph
    if options.graph_name:
        if options.graph_name not in load_all_graphs():
            die_failure(
                messages("graph_module_404").format(options.graph_name)
            )
        if not (options.report_path_filename.endswith(".html") or options.report_path_filename.endswith(".htm")):
            warn(messages("graph_output"))
            options.graph_name = None
    # check modules extra args
    if options.modules_extra_args:
        all_args = {}
        for args in options.modules_extra_args.split("&"):
            value = args.split('=')[1]
            if value.lower() == 'true':
                value = True
            elif value.lower() == 'false':
                value = False
            elif '.' in value:
                try:
                    value = float(value)
                except Exception as _:
                    del _
            elif '{' in value or '[' in value:
                try:
                    value = json.loads(value)
                except Exception as _:
                    del _
            else:
                try:
                    value = int(value)
                except Exception as _:
                    del _
            all_args[args.split('=')[0]] = value
        options.modules_extra_args = all_args
    options.timeout = float(options.timeout)
    options.time_sleep_between_requests = float(options.time_sleep_between_requests)
    options.retries = int(options.retries)
    return options
