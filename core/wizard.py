#!/usr/bin/env python
# -*- coding: utf-8 -*-

import config
from core.config_builder import _builder
from config import get_config
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
    default_config = _builder(get_config())
    targets = __input(messages(language, 118).format('the targets', default_config["targets"]),
                      default_config["targets"])
    thread_number = __input(messages(language, 118).format('the thread number', default_config["thread_number"]),
                            default_config["thread_number"])
    thread_number_host = __input(messages(language, 118)
                                 .format('the thread numbers for scan hosts', default_config["thread_number_host"]),
                                 default_config["thread_number_host"])
    log_in_file = __input(messages(language, 118).format('the output filename', default_config["log_in_file"]),
                          default_config["log_in_file"])
    scan_method = __input(messages(language, 119)
                          .format('the scan methods', ', '.join(module_name), default_config["scan_method"]),
                          default_config["scan_method"])
    exclude_method = __input(messages(language, 119)
                             .format('the scan methods to exclude', ', '.join(ex_module_name),
                                     default_config["exclude_method"]),
                             default_config["exclude_method"])
    users = __input(messages(language, 118).format('the usernames', default_config["users"]), default_config["users"])
    passwds = __input(messages(language, 118).format('the passwords', default_config["passwds"]),
                      default_config["passwds"])
    timeout_sec = __input(messages(language, 118).format('the timeout seconds', default_config["timeout_sec"]),
                          default_config["timeout_sec"])
    ports = __input(messages(language, 118).format('the port numbers', default_config["ports"]),
                    default_config["ports"])
    verbose_level = __input(messages(language, 118).format('the verbose level', default_config["verbose_level"]),
                            default_config["verbose_level"])
    socks_proxy = __input(messages(language, 118).format('the socks proxy', default_config["socks_proxy"]),
                          default_config["socks_proxy"])
    retries = __input(messages(language, 118).format('the retries number', default_config["retries"]),
                      default_config["retries"])
    graph_flag = __input(messages(language, 119)
                         .format('a graph', ', '.join(graph_flag), default_config["graph_flag"]),
                         default_config["graph_flag"])
    return [targets, thread_number, thread_number_host,
            log_in_file, scan_method, exclude_method, users,
            passwds, timeout_sec, ports, verbose_level,
            socks_proxy, retries, graph_flag]
