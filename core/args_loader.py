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

# temporary use fixed version of argparse
if os_name() == 'win32' or os_name() == 'win64':
    if version() is 2:
        from lib.argparse import argparse_v2 as argparse
    else:
        from lib.argparse import argparse_v3 as argparse
else:
    import argparse


def load_all_args(module_names, graph_names):
    # Language Options
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
            error("Please select one of these languages {0}".format(language_list))
            from core.color import finish
            finish()
            sys.exit(1)

    # Check if compatible
    check(language)
    from core.color import finish
    finish()
    # Start Parser
    parser = argparse.ArgumentParser(prog="Nettacker", add_help=False)

    # parser = OptionParser(usage=messages(language, 1),
    #                      description=messages(language, 2),
    #                      epilog=messages(language, 3))

    # Engine Options
    engineOpt = parser.add_argument_group(messages(language, 4), messages(language, 5))
    engineOpt.add_argument("-L", "--language", action="store",
                           dest="language", default="en",
                           help=messages(language, 6).format(language_list))
    engineOpt.add_argument("-v", "--verbose", action="store",
                           dest="verbose_level", default=0,
                           help=messages(language, 59))
    engineOpt.add_argument("-V", "--version", action="store_true",
                           default=False, dest="show_version",
                           help=messages(language, 60))
    engineOpt.add_argument("-c", "--update", action="store_true",
                           default=False, dest="check_update",
                           help=messages(language, 61))
    engineOpt.add_argument("-o", "--output", action="store",
                           default="results.html", dest="log_in_file",
                           help=messages(language, 11))
    engineOpt.add_argument("--graph", action="store",
                           default=None, dest="graph_flag",
                           help=messages(language, 86).format(graph_names))
    engineOpt.add_argument("-h", "--help", action="store_true",
                           default=False, dest="help_menu_flag",
                           help=messages(language, 2))

    # Target Options
    target = parser.add_argument_group(messages(language, 12), messages(language, 13))
    target.add_argument("-i", "--targets", action="store", dest="targets", default=None,
                        help=messages(language, 14))
    target.add_argument("-l", "--targets-list", action="store", dest="targets_list", default=None,
                        help=messages(language, 15))

    # Exclude Module Name
    exclude_names = module_names[:]
    exclude_names.remove('all')

    # Methods Options
    method = parser.add_argument_group("Method", messages(language, 16))
    method.add_argument("-m", "--method", action="store",
                        dest="scan_method", default=None,
                        help=messages(language, 17).format(module_names))
    method.add_argument("-x", "--exclude", action="store",
                        dest="exclude_method", default=None,
                        help=messages(language, 18).format(exclude_names))
    method.add_argument("-u", "--usernames", action="store",
                        dest="users", default=None,
                        help=messages(language, 19))
    method.add_argument("-U", "--users-list", action="store",
                        dest="users_list", default=None,
                        help=messages(language, 20))
    method.add_argument("-p", "--passwords", action="store",
                        dest="passwds", default=None,
                        help=messages(language, 21))
    method.add_argument("-P", "--passwords-list", action="store",
                        dest="passwds_list", default=None,
                        help=messages(language, 22))
    method.add_argument("-g", "--ports", action="store",
                        dest="ports", default=None,
                        help=messages(language, 23))
    method.add_argument("-T", "--timeout", action="store",
                        dest="timeout_sec", default=3.0, type=float,
                        help=messages(language, 24))
    method.add_argument("-w", "--time-sleep", action="store",
                        dest="time_sleep", default=0.0, type=float,
                        help=messages(language, 25))
    method.add_argument("-r", "--range", action="store_true",
                        default=False, dest="check_ranges",
                        help=messages(language, 7))
    method.add_argument("-s", "--sub-domains", action="store_true",
                        default=False, dest="check_subdomains",
                        help=messages(language, 8))
    method.add_argument("-t", "--thread-connection", action="store",
                        default=10, type=int, dest="thread_number",
                        help=messages(language, 9))
    method.add_argument("-M", "--thread-hostscan", action="store",
                        default=10, type=int, dest="thread_number_host",
                        help=messages(language, 10))
    method.add_argument("-R", "--proxy", action="store",
                        dest="proxies", default=None,
                        help=messages(language, 62))
    method.add_argument("--proxy-list", action="store",
                        dest="proxies_file", default=None,
                        help=messages(language, 63))
    method.add_argument("--retries", action="store",
                        dest="retries", type=int, default=3,
                        help=messages(language, 64))
    method.add_argument('--ping-before-scan', action="store_true",
                        dest='ping_flag', default=False,
                        help=messages(language,99))
    # Return Options
    return [parser, parser.parse_args()]


def check_all_required(targets, targets_list, thread_number, thread_number_host,
                       log_in_file, scan_method, exclude_method, users, users_list,
                       passwds, passwds_list, timeout_sec, ports, parser, module_names, language, verbose_level,
                       show_version, check_update, proxies, proxies_file, retries, graph_flag, help_menu_flag):
    # Checking Requirements
    # Check Help Menu
    if help_menu_flag is True:
        parser.print_help()
        write('\n\n')
        write(messages(language, 3))
        from core.color import finish
        finish()
        sys.exit(0)
    # Check version
    if show_version is True:
        from core import compatible
        from core import color
        info(messages(language, 84).format(color.color('yellow'), compatible.__version__, color.color('reset'),
                                           color.color('cyan'), compatible.__code_name__, color.color('reset'),
                                           color.color('green')))
        from core.color import finish
        finish()
        sys.exit(0)
    # Check update
    if check_update is True:
        info(messages(language, 85))
        from core.color import finish
        finish()
        sys.exit(0)
    # Check the target(s)
    if targets is None and targets_list is None:
        parser.print_help()
        write("\n")
        error(messages(language, 26))
        from core.color import finish
        finish()
        sys.exit(1)
    else:
        if targets is not None:
            targets = list(set(targets.rsplit(",")))
        elif targets_list is not None:
            try:
                targets = list(set(open(targets_list, "rb").read().rsplit()))
            except:
                error(messages(language, 27).format(targets_list))
                from core.color import finish
                finish()
                sys.exit(1)
    # Check thread number
    if thread_number > 100 or thread_number_host > 100:
        warn(messages(language, 28))
    # Check timeout number
    if timeout_sec is not None and timeout_sec >= 15:
        warn(messages(language, 29).format(timeout_sec))
    # Check scanning method
    if scan_method is not None and scan_method == "all":
        scan_method = module_names
        scan_method.remove("all")
    elif scan_method is not None and scan_method not in module_names:
        if "," in scan_method:
            scan_method = scan_method.rsplit(",")
            for sm in scan_method:
                if sm not in module_names:
                    error(messages(language, 30).format(sm))
                    from core.color import finish
                    finish()
                    sys.exit(1)
                if sm == "all":
                    scan_method = module_names
                    scan_method.remove("all")
                    break
        else:
            error(messages(language, 31).format(scan_method))
            from core.color import finish
            finish()
            sys.exit(1)
    elif scan_method is None:
        error(messages(language, 41))
        from core.color import finish
        finish()
        sys.exit(1)
    else:
        scan_method = scan_method.rsplit()
    if exclude_method is not None:
        exclude_method = exclude_method.rsplit(",")
        for exm in exclude_method:
            if exm in scan_method:
                if "all" == exm:
                    messages(language, 32)
                    from core.color import finish
                    finish()
                    sys.exit(1)
                else:
                    scan_method.remove(exm)
                    if len(scan_method) is 0:
                        messages(language, 33)
                        from core.color import finish
                        finish()
                        sys.exit(1)
            else:
                messages(language, 34).format(exm)
                from core.color import finish
                finish()
                sys.exit(1)
    # Check port(s)
    if ports is None:
        error(messages(language, 35))
        from core.color import finish
        finish()
        sys.exit(1)
    if type(ports) is not list and "-" in ports:
        ports = ports.rsplit("-")
        ports = range(int(ports[0]), int(ports[1]) + 1)
    elif type(ports) is not list:
        ports = ports.rsplit(",")
    # Check user list
    if users is None and users_list is None and scan_method is not None:
        for imethod in scan_method:
            if "_brute" in imethod:
                error(messages(language, 36))
                from core.color import finish
                finish()
                sys.exit(1)
    else:
        if users is not None:
            users = list(set(users.rsplit(",")))
        if users_list is not None:
            try:
                users = list(set(open(users_list).read().rsplit("\n")))  # fix later
            except:
                error(messages(language, 37).format(targets_list))
                from core.color import finish
                finish()
                sys.exit(1)
    # Check password list
    if passwds is None and passwds_list is None and scan_method is not None:
        for imethod in scan_method:
            if "_brute" in imethod:
                error(messages(language, 38))
                from core.color import finish
                finish()
                sys.exit(1)
    else:
        if passwds is not None:
            passwds = list(set(passwds.rsplit(",")))
        if passwds_list is not None:
            try:
                passwds = list(set(open(passwds_list).read().rsplit("\n")))  # fix later
            except:
                error(messages(language, 39).format(targets_list))
                from core.color import finish
                finish()
                sys.exit(1)
    # Check output file
    try:
        tmpfile = open(log_in_file, "w")
    except:
        error(messages(language, 40).format(log_in_file))
        from core.color import finish
        finish()
        sys.exit(1)
    # Check Proxies
    if proxies is not None:
        proxies = list(set(proxies.rsplit(',')))
    elif proxies_file is not None:
        if os.path.isfile(proxies_file):
            try:
                proxies = list(set(open(proxies_file).read().rsplit()))
            except:
                error(messages(language, 82).format(proxies_file))
                from core.color import finish
                finish()
                sys.exit(1)
        else:
            error(messages(language, 83).format(proxies_file))
            from core.color import finish
            finish()
            sys.exit(1)
    # Check Graph
    if graph_flag is not None:
        if not (len(log_in_file) >= 5 and log_in_file[-5:] == '.html') or (
                    not len(log_in_file) >= 4 and log_in_file[-4:] == '.htm'):
            error(messages(language, 87))
            from core.color import finish
            finish()
            sys.exit(1)
        if graph_flag not in load_all_graphs():
            error(messages(language, 97).format(graph_flag))
            from core.color import finish
            finish()
            sys.exit(1)

    # Return the values
    return [targets, targets_list, thread_number, thread_number_host,
            log_in_file, scan_method, exclude_method, users, users_list,
            passwds, passwds_list, timeout_sec, ports, parser, module_names, language, verbose_level, show_version,
            check_update, proxies, proxies_file, retries, graph_flag, help_menu_flag]
