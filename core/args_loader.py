#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from optparse import OptionGroup
from optparse import OptionParser
from core.alert import error
from core.alert import write
from core.alert import warn
from core.alert import messages


def load_all_args(module_names):

    # Language Options
    language_list = [lang for lang in messages(-1, 0)]
    if "-L" in sys.argv or "--language" in sys.argv:
        try:
            index = sys.argv.index("-L") + 1
        except:
            index = sys.argv.index("-language") + 1
    else:
        index = -1
    if index is -1:
        language = "en"
    else:
        language = sys.argv[index]
        if language not in language_list:
            sys.exit(error("Please select one of these languages %s"%(language_list)))

    # Start Parser
    parser = OptionParser(usage=messages(language,1), description=messages(language,2),
                          epilog=messages(language,3))
    # Engine Options
    engineOpt = OptionGroup(parser, messages(language,4), messages(language,5))
    engineOpt.add_option("-L", "--language", action="store",
                         dest="language", default="en",
                         help=messages(language,6) + " %s " % (language_list))
    # IO Options
    parser.add_option("-r", "--range", action="store_true", default=False, dest="check_ranges",
                      help=messages(language,7))
    parser.add_option("-s", "--sub-domains", action="store_true", default=False, dest="check_subdomains",
                      help=messages(language,8))
    parser.add_option("-t", "--thread-connection", action="store", default=10, type="int", dest="thread_number",
                      help=messages(language,9))
    parser.add_option("-M", "--thread-hostscan", action="store", default=10, type="int", dest="thread_number_host",
                      help=messages(language,10))
    parser.add_option("-o", "--output", action="store", default="results.txt", dest="log_in_file",
                      help=messages(language,11))

    # Target Options
    target = OptionGroup(parser, messages(language,12), messages(language,13))
    target.add_option("-i", "--targets", action="store", dest="targets", default=None,
                      help=messages(language,14))
    target.add_option("-l", "--targets-list", action="store", dest="targets_list", default=None,
                      help=messages(language,15))
    # Build Options
    parser.add_option_group(target)

    # Methods Options
    method = OptionGroup(parser, "Method", messages(language,16))
    method.add_option("-m", "--method", action="store",
                      dest="scan_method", default=None,
                      help=messages(language,17) + " %s" % (module_names))
    method.add_option("-x", "--exclude", action="store",
                      dest="exclude_method", default=None,
                      help="choose scan method to exclude %s" % (module_names))
    method.add_option("-u", "--usernames", action="store",
                      dest="users", default=None,
                      help="username(s) list, separate with \",\"")
    method.add_option("-U", "--users-list", action="store",
                      dest="users_list", default=None,
                      help="read username(s) from file")
    method.add_option("-p", "--passwords", action="store",
                      dest="passwds", default=None,
                      help="password(s) list, separate with \",\"")
    method.add_option("-P", "--passwords-list", action="store",
                      dest="passwds_list", default=None,
                      help="read passwords(s) from file")
    method.add_option("-g", "--ports", action="store",
                      dest="ports", default=None,
                      help="port(s) list, separate with \",\"")
    method.add_option("-T", "--timeout", action="store",
                      dest="timeout_sec", default=None, type="float",
                      help="read passwords(s) from file")
    method.add_option("-w", "--time-sleep", action="store",
                      dest="time_sleep", default=None, type="float",
                      help="time to sleep between each request")
    # Build Options
    parser.add_option_group(method)

    # Build Options
    parser.add_option_group(method)

    # Return Options
    return [parser,parser.parse_args()]


def check_all_required(targets, targets_list, thread_number, thread_number_host, log_in_file, scan_method,
                       exclude_method, users, users_list, passwds, passwds_list, timeout_sec, ports, parser,
                       module_names):
    # Checking Requirements
    # Check the target(s)
    if targets is None and targets_list is None:
        parser.print_help()
        write("\n")
        sys.exit(error("Cannot specify the target(s)"))
    else:
        if targets is not None:
            targets = list(set(targets.rsplit(",")))
        elif targets_list is not None:
          try:
              targets = list(set(open(targets_list,"rb").read().rsplit()))
          except:
              sys.exit(error("Cannot specify the target(s), unable to open file: %s"%(targets_list)))
    # Check thread number
    if thread_number > 100 or thread_number_host > 100:
        warn("it\"s better to use thread number lower than 100, BTW we are continuing...")
    # Check timeout number
    if timeout_sec is not None and timeout_sec >= 15:
        warn("set timeout to %s seconds, it is too big, isn\"t it ? by the way we are continuing...")
    # Check scanning method
    if scan_method is not None and scan_method == "all":
        scan_method = module_names
        scan_method.remove("all")
    elif scan_method is not None and scan_method not in module_names:
        if "," in scan_method:
            scan_method = scan_method.rsplit(",")
            for sm in scan_method:
                if sm not in module_names:
                    sys.exit(error("this scan module [%s] not found!" % (sm)))
                if sm == "all":
                    scan_method = module_names
                    scan_method.remove("all")
                    break
        else:
            sys.exit(error("this scan module [%s] not found!" % (scan_method)))
    elif scan_method is None:
        sys.exit(error("please choose your scan method!"))
    else:
        scan_method = scan_method.rsplit()
    if exclude_method is not None:
        exclude_method = exclude_method.rsplit(",")
        for exm in exclude_method:
            if exm in scan_method:
                if "all" == exm:
                    sys.exit("you cannot exclude all scan methods")
                else:
                    scan_method.remove(exm)
                    if len(scan_method) is 0:
                        sys.exit("you cannot exclude all scan methods")
            else:
                sys.exit("the %s module you selected to exclude not found!"%(exm))
    # Check port(s)
    if ports is None:
        sys.exit(error("please enter one port at least!"))
    if type(ports) is not list and "-" in ports:
        ports = ports.rsplit("-")
        ports = range(int(ports[0]), int(ports[1]) + 1)
    elif type(ports) is not list:
        ports = ports.rsplit(",")
    # Check user list
    if users is None and users_list is None and scan_method is not None:
        for imethod in scan_method:
            if "_brute" in imethod:
                sys.exit(error("this module required username(s) (list) to bruteforce!"))
    else:
        if users is not None:
            users = list(set(users.rsplit(",")))
        if users_list is not None:
            try:
                users = list(set(open(users_list).read().rsplit("\n"))) # fix later
            except:
                sys.exit(error("Cannot specify the username(s), unable to open file: %s" % (targets_list)))
    # Check password list
    if passwds is None and passwds_list is None and scan_method is not None:
            for imethod in scan_method:
                if "_brute" in imethod:
                    sys.exit(error("this module required password(s) (list) to bruteforce!"))
    else:
        if passwds is not None:
            passwds = list(set(passwds.rsplit(",")))
        if passwds_list is not None:
            try:
                passwds = list(set(open(passwds_list).read().rsplit("\n"))) # fix later
            except:
                sys.exit(error("Cannot specify the password(s), unable to open file: %s" % (targets_list)))
    # Check output file
    try:
        tmpfile = open(log_in_file,"a")
    except:
        sys.exit(error("file \"%s\" is not writable!"%(log_in_file)))

    # Return the values
    return [targets, targets_list, thread_number, thread_number_host, log_in_file, scan_method,
    exclude_method, users, users_list, passwds, passwds_list, timeout_sec, ports, parser,
    module_names]