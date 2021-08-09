#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from core.scan_targers import start_scan_processes
from core.utility import select_maximum_cpu_core
from config import nettacker_global_config
from core.load_modules import load_all_graphs
from core.load_modules import load_all_modules

def __scan(options):
    """
    call for attacks with separated config and parse ARGS

    Args:
        config: config in JSON

    Returns:
        True if success otherwise False
    """
    # Check the target(s)
    modules_list = load_all_modules()
    if options.targets:
        print(options)
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
    if options.selected_modules:

        if options.selected_modules == 'all':
            options.selected_modules = modules_list
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
            options.selected_modules = modules_list
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
                for module_name in modules_list:
                    if module_name.endswith(profile):
                        options.selected_modules.append(module_name)

    # threading & processing
    if options.set_hardware_usage not in ['low', 'normal', 'high', 'maximum']:
        die_failure(
            messages("wrong_hardware_usage")
        )
    options.set_hardware_usage = select_maximum_cpu_core(options.set_hardware_usage)

    if not options.thread_per_host >= 1:
        options.thread_per_host = 1

    if not options.parallel_module_scan >= 1:
        options.parallel_module_scan = 1

    # Check for excluding modules
    if options.excluded_modules:
        options.excluded_modules = options.excluded_modules.split(",")
        # if 'all' in options.excluded_modules:
        #     die_failure(messages("error_exclude_all"))
        for excluded_module in options.excluded_modules:
            if excluded_module in options.selected_modules:
                options.selected_modules.remove(excluded_module)
    # Check port(s)
    if options.ports:
        tmp_ports = []
        for port in options.ports.split(","):
            # try:
            if "-" in port:
                for port_number in range(int(port.split('-')[0]), int(port.split('-')[1]) + 1):
                    if port_number not in tmp_ports:
                        tmp_ports.append(port_number)
            else:
                if int(port) not in tmp_ports:
                    tmp_ports.append(int(port))
            # except Exception:
            #     die_failure(messages("ports_int"))  ##show error on api
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
    # Setting Variables
    # targets = config["targets"]
    # scan_ip_range = config["scan_ip_range"]
    # scan_subdomains = config["scan_subdomains"]
    # report_path_filename = config["report_path_filename"]
    # time_sleep_between_requests = config["time_sleep_between_requests"]
    # language = config["language"]
    # verbose_mode = config["verbose_mode"]
    # retries = config["retries"]
    # socks_proxy = config["socks_proxy"]
    # selected_modules = config["selected_modules"]
    # usernames = config["usernames"]
    # passwords = config["passwords"]
    # timeout_sec = config["timeout_sec"]
    # thread_per_host = config["thread_per_host"]
    # ports = config["ports"]
    # ping_before_scan = config["ping_before_scan"]
    # parallel_host_scan = config["parallel_host_scan"]
    # graph_name = config["graph_name"]
    # profile = config["profile"]
    # backup_ports = config["backup_ports"]

    return start_scan_processes(options)
