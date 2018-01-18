#!/usr/bin/env python
# -*- coding: utf-8 -*-

import config
from core.config_builder import _builder
from config import _core_config
from core.config_builder import _core_default_config
from core.load_modules import load_all_graphs
from core.get_input import __input
from core.alert import messages


def __wizard(targets, thread_number, thread_number_host,
             log_in_file, scan_method, exclude_method, users,
             passwds, timeout_sec, ports, verbose_level,
             socks_proxy, retries, graph_flag, language):
    # default config
    module_name = scan_method[:]
    ex_module_name = scan_method[:]
    ex_module_name.remove('all')
    default_config = _builder(_core_config(), _core_default_config())
    targets = __input(messages(language, 118).format(messages(language, 120), default_config["targets"]),
                      default_config["targets"])
    thread_number = __input(messages(language, 118).format(messages(language, 121), default_config["thread_number"]),
                            default_config["thread_number"])
    thread_number_host = __input(messages(language, 118)
                                 .format(messages(language, 122), default_config["thread_number_host"]),
                                 default_config["thread_number_host"])
    log_in_file = __input(messages(language, 118).format(messages(language, 123), default_config["log_in_file"]),
                          default_config["log_in_file"])
    scan_method = __input(messages(language, 119)
                          .format(messages(language, 124), ', '.join(module_name), default_config["scan_method"]),
                          default_config["scan_method"])
    exclude_method = __input(messages(language, 119)
                             .format(messages(language, 125), ', '.join(ex_module_name),
                                     default_config["exclude_method"]),
                             default_config["exclude_method"])
    users = __input(messages(language, 118).format(messages(language, 126), default_config["users"]),
                    default_config["users"])
    passwds = __input(messages(language, 118).format(messages(language, 127), default_config["passwds"]),
                      default_config["passwds"])
    timeout_sec = __input(messages(language, 118).format(messages(language, 128), default_config["timeout_sec"]),
                          default_config["timeout_sec"])
    ports = __input(messages(language, 118).format(messages(language, 129), default_config["ports"]),
                    default_config["ports"])
    verbose_level = __input(messages(language, 118).format(messages(language, 130), default_config["verbose_level"]),
                            default_config["verbose_level"])
    socks_proxy = __input(messages(language, 118).format(messages(language, 131), default_config["socks_proxy"]),
                          default_config["socks_proxy"])
    retries = __input(messages(language, 118).format(messages(language, 132), default_config["retries"]),
                      default_config["retries"])
    graph_flag = __input(messages(language, 119)
                         .format(messages(language, 133), ', '.join(graph_flag), default_config["graph_flag"]),
                         default_config["graph_flag"])
    return [targets, thread_number, thread_number_host,
            log_in_file, scan_method, exclude_method, users,
            passwds, timeout_sec, ports, verbose_level,
            socks_proxy, retries, graph_flag]
