#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from core.scan_targers import start_scan_processes


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
    scan_ip_range = config["scan_ip_range"]
    scan_subdomains = config["scan_subdomains"]
    output_file = config["output_file"]
    time_sleep_between_requests = config["time_sleep_between_requests"]
    language = config["language"]
    verbose_mode = config["verbose_mode"]
    retries = config["retries"]
    socks_proxy = config["socks_proxy"]
    selected_modules = config["selected_modules"]
    usernames = config["usernames"]
    passwords = config["passwords"]
    timeout_sec = config["timeout_sec"]
    thread_per_host = config["thread_per_host"]
    ports = config["ports"]
    ping_before_scan = config["ping_before_scan"]
    parallel_host_scan = config["parallel_host_scan"]
    graph_name = config["graph_name"]
    profile = config["profile"]
    backup_ports = config["backup_ports"]

    return start_scan_processes(targets, scan_ip_range, scan_subdomains,
                            output_file,
                            time_sleep_between_requests, language, verbose_mode, retries,
                            socks_proxy, usernames, passwords, timeout_sec,
                            thread_per_host,
                            ports, ping_before_scan,
                            backup_ports, selected_modules, parallel_host_scan,
                            graph_name, profile, True)
