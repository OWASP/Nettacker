#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
from core.alert import error
from core.alert import write
from core.alert import warn
from core.alert import info
from core.alert import messages
from core.compatible import check
from core.compatible import version
from core.compatible import os_name
from core.load_modules import load_all_graphs
from core.config import _core_config
from core.config_builder import _builder
from core._die import __die_success
from core._die import __die_failure
from core.color import finish
from core.wizard import __wizard
from core.config_builder import _core_default_config
from core.config_builder import default_profiles
from core.config import _profiles
from core.alert import write_to_api_console
from core.update import _update_check

# temporary use fixed version of argparse
if os_name() == "win32" or os_name() == "win64":
    if version() is 2:
        from lib.argparse.v2 import argparse
    else:
        from lib.argparse.v3 import argparse
else:
    import argparse


def load_all_args(module_names, graph_names):
    """
    create the ARGS and help menu

    Args:
        module_names: all module names
        graph_names: all graph names

    Returns:
        the parser, the ARGS
    """
    # Language Options
    # import libs
    default_config = _builder(_core_config(), _core_default_config())
    _all_profiles = [key for key in _builder(_profiles(), default_profiles())]
    _all_profiles.append("all")
    language_list = [lang for lang in messages(-1, 0)]
    if "-L" in sys.argv or "--language" in sys.argv:
        try:
            index = sys.argv.index("-L") + 1
        except:
            index = sys.argv.index("--language") + 1
    else:
        index = -1
    if index is -1:
        language = "en"
    else:
        _error_flag = False
        try:
            language = sys.argv[index]
        except:
            _error_flag = True
        if _error_flag or language not in language_list:
            __die_failure(
                "Please select one of these languages {0}".format(language_list))

    # Check if compatible
    check(language)
    finish()
    # Start Parser
    parser = argparse.ArgumentParser(prog="Nettacker", add_help=False)

    # parser = OptionParser(usage=messages(language,"options"),
    #                      description=messages(language,"help_menu"),
    #                      epilog=messages(language,"license"))

    # Engine Options
    engineOpt = parser.add_argument_group(
        messages(language, "engine"), messages(language, "engine_input"))
    engineOpt.add_argument("-L", "--language", action="store",
                           dest="language", default=default_config["language"],
                           help=messages(language, "select_language").format(language_list))
    engineOpt.add_argument("-v", "--verbose", action="store", type=int,
                           dest="verbose_level", default=default_config["verbose_level"],
                           help=messages(language, "verbose_level"))
    engineOpt.add_argument("-V", "--version", action="store_true",
                           default=default_config[
                               "show_version"], dest="show_version",
                           help=messages(language, "software_version"))
    engineOpt.add_argument("-c", "--update", action="store_true",
                           default=default_config[
                               "check_update"], dest="check_update",
                           help=messages(language, "check_updates"))
    engineOpt.add_argument("-o", "--output", action="store",
                           default=default_config[
                               "log_in_file"], dest="log_in_file",
                           help=messages(language, "save_logs"))
    engineOpt.add_argument("--graph", action="store",
                           default=default_config[
                               "graph_flag"], dest="graph_flag",
                           help=messages(language, "available_graph").format(graph_names))
    engineOpt.add_argument("-h", "--help", action="store_true",
                           default=default_config[
                               "help_menu_flag"], dest="help_menu_flag",
                           help=messages(language, "help_menu"))
    engineOpt.add_argument("-W", "--wizard", action="store_true",
                           default=default_config[
                               "wizard_mode"], dest="wizard_mode",
                           help=messages(language, "wizard_mode"))
    engineOpt.add_argument("--profile", action="store",
                           default=default_config["profile"], dest="profile",
                           help=messages(language, "select_profile").format(_all_profiles))

    # Target Options
    target = parser.add_argument_group(
        messages(language, "target"), messages(language, "target_input"))
    target.add_argument("-i", "--targets", action="store", dest="targets",
                        default=default_config["targets"], help=messages(language, "target_list"))
    target.add_argument("-l", "--targets-list", action="store", dest="targets_list",
                        default=default_config["targets_list"], help=messages(language, "read_target"))

    # Exclude Module Name
    exclude_names = module_names[:]
    exclude_names.remove("all")

    # Methods Options
    method = parser.add_argument_group(
        messages(language, "Method"), messages(language, "scan_method_options"))
    method.add_argument("-m", "--method", action="store",
                        dest="scan_method", default=default_config["scan_method"],
                        help=messages(language, "choose_scan_method").format(module_names))
    method.add_argument("-x", "--exclude", action="store",
                        dest="exclude_method", default=default_config["exclude_method"],
                        help=messages(language, "exclude_scan_method").format(exclude_names))
    method.add_argument("-u", "--usernames", action="store",
                        dest="users", default=default_config["users"],
                        help=messages(language, "username_list"))
    method.add_argument("-U", "--users-list", action="store",
                        dest="users_list", default=default_config["users_list"],
                        help=messages(language, "username_from_file"))
    method.add_argument("-p", "--passwords", action="store",
                        dest="passwds", default=default_config["passwds"],
                        help=messages(language, "password_seperator"))
    method.add_argument("-P", "--passwords-list", action="store",
                        dest="passwds_list", default=default_config["passwds_list"],
                        help=messages(language, "read_passwords"))
    method.add_argument("-g", "--ports", action="store",
                        dest="ports", default=default_config["ports"],
                        help=messages(language, "port_seperator"))
    method.add_argument("-T", "--timeout", action="store",
                        dest="timeout_sec", default=default_config["timeout_sec"], type=float,
                        help=messages(language, "read_passwords"))
    method.add_argument("-w", "--time-sleep", action="store",
                        dest="time_sleep", default=default_config["time_sleep"], type=float,
                        help=messages(language, "time_to_sleep"))
    method.add_argument("-r", "--range", action="store_true",
                        default=default_config[
                            "check_ranges"], dest="check_ranges",
                        help=messages(language, "range"))
    method.add_argument("-s", "--sub-domains", action="store_true",
                        default=default_config[
                            "check_subdomains"], dest="check_subdomains",
                        help=messages(language, "subdomains"))
    method.add_argument("-t", "--thread-connection", action="store",
                        default=default_config[
                            "thread_number"], type=int, dest="thread_number",
                        help=messages(language, "thread_number_connections"))
    method.add_argument("-M", "--thread-hostscan", action="store",
                        default=default_config["thread_number_host"], type=int,
                        dest="thread_number_host", help=messages(language, "thread_number_hosts"))
    method.add_argument("-R", "--socks-proxy", action="store",
                        dest="socks_proxy", default=default_config["socks_proxy"],
                        help=messages(language, "outgoing_proxy"))
    method.add_argument("--retries", action="store",
                        dest="retries", type=int, default=default_config["retries"],
                        help=messages(language, "connection_retries"))
    method.add_argument("--ping-before-scan", action="store_true",
                        dest="ping_flag", default=default_config["ping_flag"],
                        help=messages(language, "ping_before_scan"))
    method.add_argument("--method-args", action="store",
                        dest="methods_args", default=default_config["methods_args"],
                        help=messages(language, "method_inputs"))
    method.add_argument("--method-args-list", action="store_true",
                        dest="method_args_list", default=default_config["method_args_list"],
                        help=messages(language, "list_methods"))

    # API Options
    api = parser.add_argument_group(
        messages(language, "API"), messages(language, "API_options"))
    api.add_argument("--start-api", action="store_true",
                     dest="start_api", default=default_config["start_api"],
                     help=messages(language, "start_API"))
    api.add_argument("--api-host", action="store",
                     dest="api_host", default=default_config["api_host"],
                     help=messages(language, "API_host"))
    api.add_argument("--api-port", action="store",
                     dest="api_port", default=default_config["api_port"],
                     help=messages(language, "API_port"))
    api.add_argument("--api-debug-mode", action="store_true",
                     dest="api_debug_mode", default=default_config["api_debug_mode"],
                     help=messages(language, "API_debug"))
    api.add_argument("--api-access-key", action="store",
                     dest="api_access_key", default=default_config["api_access_key"],
                     help=messages(language, "API_access_key"))
    api.add_argument("--api-client-white-list", action="store_true",
                     dest="api_client_white_list", default=default_config["api_client_white_list"],
                     help=messages(language, "white_list_API"))
    api.add_argument("--api-client-white-list-ips", action="store",
                     dest="api_client_white_list_ips", default=default_config["api_client_white_list_ips"],
                     help=messages(language, "define_whie_list"))
    api.add_argument("--api-access-log", action="store_true",
                     dest="api_access_log", default=default_config["api_access_log"],
                     help=messages(language, "gen_API_access_log"))
    api.add_argument("--api-access-log-filename", action="store",
                     dest="api_access_log_filename", default=default_config["api_access_log_filename"],
                     help=messages(language, "API_access_log_file"))

    # Return Options
    return [parser, parser.parse_args(), default_config["startup_check_for_update"]]


def check_all_required(targets, targets_list, thread_number, thread_number_host,
                       log_in_file, scan_method, exclude_method, users, users_list,
                       passwds, passwds_list, timeout_sec, ports, parser, module_names, language, verbose_level,
                       show_version, check_update, socks_proxy, retries, graph_flag, help_menu_flag, methods_args,
                       method_args_list, wizard_mode, profile, start_api, api_host, api_port, api_debug_mode,
                       api_access_key, api_client_white_list, api_client_white_list_ips, api_access_log,
                       api_access_log_filename):
    """
    check all rules and requirements for ARGS

    Args:
        targets: targets from CLI
        targets_list: targets_list from CLI
        thread_number: thread numbers from CLI
        thread_number_host: thread number for hosts from CLI
        log_in_file: output file from CLI
        scan_method: modules from CLI
        exclude_method: exclude modules from CLI
        users: usernames from CLI
        users_list: username file from CLI
        passwds: passwords from CLI
        passwds_list: passwords file from CLI
        timeout_sec: timeout seconds from CLI
        ports: ports from CLI
        parser: parser (argparse)
        module_names: all module names
        language: language from CLI
        verbose_level: verbose level from CLI
        show_version: show version flag from CLI
        check_update: check for update flag from CLI
        socks_proxy: socks proxy from CLI
        retries: retries from from CLI
        graph_flag: graph name from CLI
        help_menu_flag: help menu flag from CLI
        methods_args: modules ARGS flag from CLI
        method_args_list: modules ARGS from CLI
        wizard_mode: wizard mode flag from CLI
        profile: profiles from CLI
        start_api: start API flag from CLI
        api_host: API host from CLI
        api_port: API port from CLI
        api_debug_mode: API debug mode flag from CLI
        api_access_key: API access key from CLI
        api_client_white_list: API client white list flag from CLI
        api_client_white_list_ips: API client white list IPs from CLI
        api_access_log: API access log log flag from CLI
        api_access_log_filename: API access log filename from CLI

    Returns:
        all ARGS with applied rules
    """
    # Checking Requirements
    # import libs
    from core import compatible
    # Check Help Menu
    if help_menu_flag:
        parser.print_help()
        write("\n\n")
        write(messages(language, "license"))
        __die_success()
    # Check if method args list called
    if method_args_list:
        from core.load_modules import load_all_method_args
        load_all_method_args(language)
        __die_success()
    # Check version
    if show_version:
        from core import color
        info(messages(language, "current_version").format(color.color("yellow"), compatible.__version__,
                                                          color.color("reset"),
                                                          color.color("cyan"), compatible.__code_name__, color.color(
                "reset"),
                                                          color.color("green")))
        __die_success()
    # API mode
    if start_api:
        from api.engine import _start_api
        from core.targets import target_type
        from core.ip import _generate_IPRange

        try:
            api_port = int(api_port)
        except:
            __die_failure(messages(language, "API_port_int"))
        if api_client_white_list:
            if type(api_client_white_list_ips) != type([]):
                api_client_white_list_ips = list(
                    set(api_client_white_list_ips.rsplit(",")))
            hosts = []
            for data in api_client_white_list_ips:
                if target_type(data) == "SINGLE_IPv4":
                    if data not in hosts:
                        hosts.append(data)
                elif target_type(data) == "RANGE_IPv4":
                    for cidr in _generate_IPRange(data):
                        for ip in cidr:
                            if ip not in hosts:
                                hosts.append(ip)
                elif target_type(data) == "CIDR_IPv4":
                    for ip in _generate_IPRange(data):
                        if ip not in hosts:
                            hosts.append(str(ip))
                else:
                    __die_failure(messages(language, "unknown_ip_input"))
            api_client_white_list_ips = hosts[:]
        if api_access_log:
            try:
                f = open(api_access_log_filename, 'a')
            except:
                write_to_api_console(
                    " * " + messages(language, "file_write_error").format(api_access_log_filename) + "\n")
                __die_failure("")
        _start_api(api_host, api_port, api_debug_mode, api_access_key, api_client_white_list,
                   api_client_white_list_ips, api_access_log, api_access_log_filename, language)
    # Wizard mode
    if wizard_mode:
        (targets, thread_number, thread_number_host,
         log_in_file, scan_method, exclude_method, users,
         passwds, timeout_sec, ports, verbose_level,
         socks_proxy, retries, graph_flag) = \
            __wizard(
                targets, thread_number, thread_number_host,
                log_in_file, module_names, exclude_method, users,
                passwds, timeout_sec, ports, verbose_level,
                socks_proxy, retries, load_all_graphs(), language
            )
    # Check the target(s)
    if targets is None and targets_list is None:
        parser.print_help()
        write("\n")
        __die_failure(messages(language, "error_target"))
    # Select a Profile
    if scan_method is None and profile is None:
        __die_failure(messages(language, "scan_method_select"))
    if profile is not None:
        if scan_method is None:
            scan_method = ""
        else:
            scan_method += ","
        _all_profiles = _builder(_profiles(), default_profiles())
        if "all" in profile.rsplit(","):
            profile = ",".join(_all_profiles)
        tmp_sm = scan_method
        for pr in profile.rsplit(","):
            try:
                for sm in _all_profiles[pr]:
                    if sm not in tmp_sm.rsplit(","):
                        tmp_sm += sm + ","
            except:
                __die_failure(messages(language, "profile_404").format(pr))
        if tmp_sm[-1] == ",":
            tmp_sm = tmp_sm[0:-1]
        scan_method = ",".join(list(set(tmp_sm.rsplit(","))))
    # Check Socks
    if socks_proxy is not None:
        e = False
        if socks_proxy.startswith("socks://"):
            socks_flag = 5
            socks_proxy = socks_proxy.replace("socks://", "")
        elif socks_proxy.startswith("socks5://"):
            socks_flag = 5
            socks_proxy = socks_proxy.replace("socks5://", "")
        elif socks_proxy.startswith("socks4://"):
            socks_flag = 4
            socks_proxy = socks_proxy.replace("socks4://", "")
        else:
            socks_flag = 5
        if "://" in socks_proxy:
            socks_proxy = socks_proxy.rsplit("://")[1].rsplit("/")[0]
        try:
            if len(socks_proxy.rsplit(":")) < 2 or len(socks_proxy.rsplit(":")) > 3:
                e = True
            elif len(socks_proxy.rsplit(":")) is 2 and socks_proxy.rsplit(":")[1] == "":
                e = True
            elif len(socks_proxy.rsplit(":")) is 3 and socks_proxy.rsplit(":")[2] == "":
                e = True
        except:
            e = True
        if e:
            __die_failure(messages(language, "valid_socks_address"))
        if socks_flag is 4:
            socks_proxy = "socks4://" + socks_proxy
        if socks_flag is 5:
            socks_proxy = "socks5://" + socks_proxy
    # Check update
    if check_update and _update_check(language):
        from core.update import _update
        _update(compatible.__version__,
                compatible.__code_name__, language, socks_proxy)
        __die_success()
    else:
        if targets is not None:
            targets = list(set(targets.rsplit(",")))
        elif targets_list is not None:
            try:
                targets = list(set(open(targets_list, "rb").read().rsplit()))
            except:
                __die_failure(
                    messages(language, "error_target_file").format(targets_list))
    # Check thread number
    if thread_number > 101 or thread_number_host > 101:
        warn(messages(language, "thread_number_warning"))
    # Check timeout number
    if timeout_sec is not None and timeout_sec >= 15:
        warn(messages(language, "set_timeout").format(timeout_sec))
    # Check scanning method
    if scan_method is not None and "all" in scan_method.rsplit(","):
        scan_method = module_names
        scan_method.remove("all")
    elif scan_method is not None and len(scan_method.rsplit(",")) is 1 and "*_" not in scan_method:
        if scan_method in module_names:
            scan_method = scan_method.rsplit()
        else:
            __die_failure(
                messages(language, "scan_module_not_found").format(scan_method))
    else:
        if scan_method is not None:
            if scan_method not in module_names:
                if "*_" in scan_method or "," in scan_method:
                    scan_method = scan_method.rsplit(",")
                    scan_method_tmp = scan_method[:]
                    for sm in scan_method_tmp:
                        scan_method_error = True
                        if sm.startswith("*_"):
                            scan_method.remove(sm)
                            found_flag = False
                            for mn in module_names:
                                if mn.endswith("_" + sm.rsplit("*_")[1]):
                                    scan_method.append(mn)
                                    scan_method_error = False
                                    found_flag = True
                            if found_flag is False:
                                __die_failure(
                                    messages(language, "module_pattern_404").format(sm))
                        elif sm == "all":
                            scan_method = module_names
                            scan_method_error = False
                            scan_method.remove("all")
                            break
                        elif sm in module_names:
                            scan_method_error = False
                        elif sm not in module_names:
                            __die_failure(
                                messages(language, "scan_module_not_found").format(sm))
                else:
                    scan_method_error = True
            if scan_method_error:
                __die_failure(
                    messages(language, "scan_module_not_found").format(scan_method))
        else:
            __die_failure(messages(language, "scan_method_select"))
    scan_method = list(set(scan_method))
    # Check for exluding scanning method
    if exclude_method is not None:
        exclude_method = exclude_method.rsplit(",")
        for exm in exclude_method:
            if exm in scan_method:
                if "all" == exm:
                    __die_failure(messages(language, "error_exclude_all"))
                else:
                    scan_method.remove(exm)
                    if len(scan_method) is 0:
                        __die_failure(
                            messages(language, "error_exclude_all"))
            else:
                __die_failure(
                    messages(language, "exclude_module_error").format(exm))
    # Check port(s)
    if type(ports) is not list and ports is not None:
        tmp_ports = []
        for port in ports.rsplit(','):
            try:
                if '-' not in port:
                    if int(port) not in tmp_ports:
                        tmp_ports.append(int(port))
                else:
                    t_ports = range(
                        int(port.rsplit('-')[0]), int(port.rsplit('-')[1]) + 1)
                    for p in t_ports:
                        if p not in tmp_ports:
                            tmp_ports.append(p)
            except:
                __die_failure(messages(language, "ports_int"))
        if len(tmp_ports) is 0:
            ports = None
        else:
            ports = tmp_ports[:]
    # Check user list
    if users is not None:
        users = list(set(users.rsplit(",")))
    elif users_list is not None:
        try:
            # fix later
            users = list(set(open(users_list).read().rsplit("\n")))
        except:
            __die_failure(
                messages(language, "error_username").format(targets_list))
    # Check password list
    if passwds is not None:
        passwds = list(set(passwds.rsplit(",")))
    if passwds_list is not None:
        try:
            passwds = list(
                set(open(passwds_list).read().rsplit("\n")))  # fix later
        except:
            __die_failure(
                messages(language, "error_password_file").format(targets_list))
    # Check output file
    try:
        tmpfile = open(log_in_file, "w")
    except:
        __die_failure(
            messages(language, "file_write_error").format(log_in_file))
    # Check Graph
    if graph_flag is not None:
        if graph_flag not in load_all_graphs():
            __die_failure(
                messages(language, "graph_module_404").format(graph_flag))
        if not (log_in_file.endswith(".html") or log_in_file.endswith(".htm")):
            warn(messages(language, "graph_output"))
            graph_flag = None
    # Check Methods ARGS
    if methods_args is not None:
        new_methods_args = {}
        methods_args = methods_args.rsplit("&")
        for imethod_args in methods_args:
            if len(imethod_args.rsplit("=")) is 2:
                if imethod_args.rsplit("=")[1].startswith("read_from_file:"):
                    try:
                        read_data = list(
                            set(open(imethod_args.rsplit("=read_from_file:")[1]).read().rsplit("\n")))
                    except:
                        __die_failure(messages(language, "error_reading_file"))
                    new_methods_args[imethod_args.rsplit("=")[0]] = read_data
                else:
                    new_methods_args[imethod_args.rsplit("=")[0]] = imethod_args.rsplit("=")[
                        1].rsplit(",")
            else:
                new_methods_args[imethod_args] = ["True"]
        methods_args = new_methods_args
    # Return the values
    return [targets, targets_list, thread_number, thread_number_host,
            log_in_file, scan_method, exclude_method, users, users_list,
            passwds, passwds_list, timeout_sec, ports, parser, module_names, language, verbose_level,
            show_version, check_update, socks_proxy, retries, graph_flag, help_menu_flag, methods_args,
            method_args_list, wizard_mode, profile, start_api, api_host, api_port, api_debug_mode,
            api_access_key, api_client_white_list, api_client_white_list_ips, api_access_log,
            api_access_log_filename]
