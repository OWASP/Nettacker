#!/usr/bin/env python
# -*- coding: utf-8 -*-

from core.attack import __go_for_attacks


def __scan(config):
    """
    call for attacks with separated config and parse ARGS

    Args:
        config: config in JSON

    Returns:
        True if success otherwise False
    """
    # Setting Variables
    targets = config["targets"]
    check_ranges = config["check_ranges"]
    check_subdomains = config["check_subdomains"]
    log_in_file = config["log_in_file"]
    time_sleep = config["time_sleep"]
    language = config["language"]
    verbose_level = config["verbose_level"]
    retries = config["retries"]
    socks_proxy = config["socks_proxy"]
    scan_method = config["scan_method"]
    users = config["users"]
    passwds = config["passwds"]
    timeout_sec = config["timeout_sec"]
    thread_number = config["thread_number"]
    ports = config["ports"]
    ping_flag = config["ping_flag"]
    methods_args = config["methods_args"]
    thread_number_host = config["thread_number_host"]
    graph_flag = config["graph_flag"]
    profile = config["profile"]
    backup_ports = config["backup_ports"]

    return __go_for_attacks(targets, check_ranges, check_subdomains, log_in_file, time_sleep, language, verbose_level,
                            retries,
                            socks_proxy, users, passwds, timeout_sec, thread_number, ports, ping_flag, methods_args,
                            backup_ports, scan_method, thread_number_host, graph_flag, profile, True)
