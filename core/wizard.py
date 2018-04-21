#!/usr/bin/env python
# -*- coding: utf-8 -*-

from core.config_builder import _builder
from core.config import _core_config
from core.config_builder import _core_default_config
from core.load_modules import load_all_graphs
from core.get_input import __input
from core.alert import messages


def __wizard(targets, thread_number, thread_number_host,
             log_in_file, scan_method, exclude_method, users,
             passwds, timeout_sec, ports, verbose_level,
             socks_proxy, retries, graph_flag, language):
    """
    start the framework in wizard mode

    Args:
        targets: targets (default value)
        thread_number: thread number (default value)
        thread_number_host: thread number for hosts (default value)
        log_in_file: output filename (default value)
        scan_method: module names (default value)
        exclude_method: excluded module names (default value)
        users: usernames (default value)
        passwds: passwords (default value)
        timeout_sec: timeout seconds (default value)
        ports: port numbers (default value)
        verbose_level: verbose level number (default value)
        socks_proxy: socks proxy (default value)
        retries: retries number (default value)
        graph_flag: graph name (default value)
        language: language

    Returns:
        an array with user inputs
    """
    # default config
    module_name = scan_method[:]
    ex_module_name = scan_method[:]
    ex_module_name.remove('all')
    default_config = _builder(_core_config(), _core_default_config())
    targets = __input(
        messages(language, "enter_default").format(messages(language, "all_targets"), default_config["targets"]),
        default_config["targets"])
    thread_number = __input(messages(language, "enter_default").format(messages(language, "all_thread_numbers"),
                                                                       default_config["thread_number"]),
                            default_config["thread_number"])
    try:
        thread_number = int(thread_number)
    except:
        thread_number = default_config["thread_number"]
    thread_number_host = __input(messages(language, "enter_default")
                                 .format(messages(language, "thread_number_hosts"),
                                         default_config["thread_number_host"]),
                                 default_config["thread_number_host"])
    try:
        thread_number_host = int(thread_number_host)
    except:
        thread_number_host = default_config["thread_number_host"]
    log_in_file = __input(
        messages(language, "enter_default").format(messages(language, "out_file"), default_config["log_in_file"]),
        default_config["log_in_file"])
    scan_method = __input(messages(language, "enter_choices_default")
                          .format(messages(language, "all_scan_methods"), ', '.join(module_name),
                                  default_config["scan_method"]),
                          default_config["scan_method"])
    exclude_method = __input(messages(language, "enter_choices_default")
                             .format(messages(language, "all_scan_methods_exclude"), ', '.join(ex_module_name),
                                     default_config["exclude_method"]),
                             default_config["exclude_method"])
    users = __input(
        messages(language, "enter_default").format(messages(language, "all_usernames"), default_config["users"]),
        default_config["users"])
    passwds = __input(
        messages(language, "enter_default").format(messages(language, "all_passwords"), default_config["passwds"]),
        default_config["passwds"])
    timeout_sec = __input(messages(language, "enter_default").format(messages(language, "timeout_seconds"),
                                                                     default_config["timeout_sec"]),
                          default_config["timeout_sec"])
    try:
        timeout_sec = int(timeout_sec)
    except:
        timeout_sec = default_config["timeout_sec"]
    ports = __input(
        messages(language, "enter_default").format(messages(language, "all_ports"), default_config["ports"]),
        default_config["ports"])
    verbose_level = __input(messages(language, "enter_default").format(messages(language, "all_verbose_level"),
                                                                       default_config["verbose_level"]),
                            default_config["verbose_level"])
    socks_proxy = __input(messages(language, "enter_default").format(messages(language, "all_socks_proxy"),
                                                                     default_config["socks_proxy"]),
                          default_config["socks_proxy"])
    retries = __input(
        messages(language, "enter_default").format(messages(language, "retries_number"), default_config["retries"]),
        default_config["retries"])
    try:
        retries = int(retries)
    except:
        retries = default_config["retries"]
    graph_flag = __input(messages(language, "enter_choices_default")
                         .format(messages(language, "graph"), ', '.join(graph_flag), default_config["graph_flag"]),
                         default_config["graph_flag"])
    return [targets, thread_number, thread_number_host,
            log_in_file, scan_method, exclude_method, users,
            passwds, timeout_sec, ports, verbose_level,
            socks_proxy, retries, graph_flag]
