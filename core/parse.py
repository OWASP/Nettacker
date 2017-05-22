#!/usr/bin/env python

import threading
import time
import os
import datetime
import random
import string
from optparse import OptionGroup
from optparse import OptionParser
from core.targets import analysis
from core.attack import start_attack
from core.alert import *
from core.log import sort_logs


def load():
    write('\n\n')
    info('Nettacker engine started ...')

    # module_names = ['smtp_brute', 'ftp_brute', 'rdp_brute', 'ssh_brute', 'http_brute', 'mysql_brute', 'mssql_brute']
    module_names = ['all','smtp_brute','port_scan','ftp_brute','ssh_brute','scada_scan']

    parser = OptionParser(usage='python nettacker.py [options]', description='Nettacker Help Menu',
                          epilog='Please read license and agreements https://github.com/Nettacker/Nettacker')

    parser.add_option('-r', '--range', action='store_true', default=False, dest='check_ranges',
                      help='scan all IPs in range')
    parser.add_option('-s', '--sub-domains', action='store_true', default=False, dest='check_subdomains',
                      help='find and scan subdomains')
    parser.add_option('-t', '--thread-connection', action='store', default=10, type='int', dest='thread_number',
                      help='thread numbers for connections to a host')
    parser.add_option('-M', '--thread-hostscan', action='store', default=10, type='int', dest='thread_number_host',
                      help='thread numbers for scan hosts')
    parser.add_option('-o', '--output', action='store', default='results.txt',  dest='log_in_file',
                      help='save all logs in file (results.txt, results.html)')

    # Target Options
    target = OptionGroup(parser, "Target", "Target input options")
    target.add_option('-i', '--targets', action='store', dest='targets', default=None,
                      help='target(s) list, separate with ","')
    target.add_option('-l', '--targets-list', action='store', dest='targets_list', default=None,
                      help='read target(s) from file')
    parser.add_option_group(target)

    # Methods Options
    method = OptionGroup(parser, "Method", "Scan method options")
    method.add_option('-m', '--method', action='store',
                      dest='scan_method', default=None,
                      help='choose scan method %s' % (module_names))
    method.add_option('-x', '--exclude', action='store',
                      dest='exclude_method', default=None,
                      help='choose scan method to exclude %s' % (module_names))
    method.add_option('-u', '--usernames', action='store',
                      dest='users', default=None,
                      help='username(s) list, separate with ","')
    method.add_option('-U', '--users-list', action='store',
                      dest='users_list', default=None,
                      help='read username(s) from file')
    method.add_option('-p', '--passwords', action='store',
                      dest='passwds', default=None,
                      help='password(s) list, separate with ","')
    method.add_option('-P', '--passwords-list', action='store',
                      dest='passwds_list', default=None,
                      help='read passwords(s) from file')
    method.add_option('-g', '--ports', action='store',
                      dest='ports', default=[21,22,23,25,80,110,143,443,445,465,587,989,990,993,995,1080,1433,3306,3389,5900,5901],
                      help='port(s) list, separate with ","')
    method.add_option('-T', '--timeout', action='store',
                      dest='timeout_sec', default=None, type='float',
                      help='read passwords(s) from file')

    parser.add_option_group(method)

    # Parse ARGVs
    (options, args) = parser.parse_args()

    # Checking Requirements
    check_ranges = options.check_ranges
    check_subdomains = options.check_subdomains
    targets = options.targets
    targets_list = options.targets_list
    thread_number = options.thread_number
    thread_number_host = options.thread_number_host
    log_in_file = options.log_in_file
    scan_method = options.scan_method
    exclude_method = options.exclude_method
    users = options.users
    users_list = options.users_list
    passwds = options.passwds
    passwds_list = options.passwds_list
    timeout_sec = options.timeout_sec
    ports = options.ports
    if targets is None and targets_list is None:
        parser.print_help()
        write('\n')
        sys.exit(error('Cannot specify the target(s)'))
    else:
        if targets is not None:
            targets = list(set(targets.rsplit(',')))
        elif targets_list is not None:
          try:
              targets = list(set(open(targets_list,'rb').read().rsplit()))
          except:
              sys.exit(error('Cannot specify the target(s), unable to open file: %s'%(targets_list)))

    if thread_number > 100:
        warn('it\'s better to use thread number lower than 100, BTW we are continuing...')
    if timeout_sec is not None and timeout_sec >= 15:
        warn('set timeout to %s seconds, it is too big, isn\'t it ? by the way we are continuing...')
    if scan_method is not None and scan_method == 'all':
        scan_method = module_names
        scan_method.remove('all')
    elif scan_method is not None and scan_method not in module_names:
        if ',' in scan_method:
            scan_method = scan_method.rsplit(',')
            for sm in scan_method:
                if sm not in module_names:
                    sys.exit(error('this scan module [%s] not found!' % (sm)))
                if sm == 'all':
                    scan_method = module_names
                    scan_method.remove('all')
                    break
        else:
            sys.exit(error('this scan module [%s] not found!' % (scan_method)))
    elif scan_method is None:
        sys.exit(error('please choose your scan method!'))
    else:
        scan_method = scan_method.rsplit()
    if exclude_method is not None:
        exclude_method = exclude_method.rsplit(',')
        for exm in exclude_method:
            if exm in scan_method:
                if 'all' == exm:
                    sys.exit('you cannot exclude all scan methods')
                else:
                    scan_method.remove(exm)
                    if len(scan_method) is 0:
                        sys.exit('you cannot exclude all scan methods')
            else:
                sys.exit('the %s module you selected to exclude not found!'%(exm))
    if type(ports) is not list and '-' in ports:
        ports = ports.rsplit('-')
        ports = range(int(ports[0]), int(ports[1]) + 1)
    elif type(ports) is not list:
        ports = ports.rsplit(',')
    if users is None and users_list is None and scan_method is not None and scan_method[-6:] == '_brute':
        sys.exit(error('this module required username(s) (list) to bruteforce!'))
    else:
        if users is not None:
            users = list(set(users.rsplit(',')))
        if users_list is not None:
            try:
                users = list(set(open(users_list).read().rsplit('\n'))) # fix later
            except:
                sys.exit(error('Cannot specify the username(s), unable to open file: %s' % (targets_list)))
    if passwds is None and passwds_list is None and scan_method is not None and scan_method[-6:] == '_brute':
            sys.exit(error('this module required password(s) (list) to bruteforce!'))
    else:
        if passwds is not None:
            passwds = list(set(passwds.rsplit(',')))
        if passwds_list is not None:
            try:
                passwds = list(set(open(passwds_list).read().rsplit('\n'))) # fix later
            except:
                sys.exit(error('Cannot specify the password(s), unable to open file: %s' % (targets_list)))
    suff = str(datetime.datetime.now()).replace(' ', '_').replace(':', '-') + '_' + ''.join(
        random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
    subs_temp = 'tmp/subs_temp_%s' % (suff)
    range_temp = 'tmp/ranges_%s' % (suff)
    total_targets = -1
    for total_targets,_ in enumerate(analysis(targets, check_ranges, check_subdomains,subs_temp,range_temp,log_in_file)):
        pass
    total_targets += 1
    total_targets = total_targets * len(scan_method)
    targets = analysis(targets, check_ranges, check_subdomains,subs_temp,range_temp,log_in_file)
    threads = []
    trying = 0
    for target in targets:
        for sm in scan_method:
            trying += 1
            t = threading.Thread(target=start_attack, args=(
                str(target).rsplit()[0], trying, total_targets, sm, users, passwds, timeout_sec, thread_number,
                ports, log_in_file))
            threads.append(t)
            t.start()
            while 1:
                n = 0
                for thread in threads:
                    if thread.isAlive() is True:
                        n += 1
                    else:
                        threads.remove(thread)
                if n >= thread_number_host:
                    time.sleep(0.1)
                else:
                    break
    while 1:
        n = True
        for thread in threads:
            if thread.isAlive() is True:
                n = False
        time.sleep(0.1)
        if n is True:
            break
    info('removing temp files!')
    os.remove(subs_temp)
    os.remove(range_temp)
    info('sorting results!')
    sort_logs(log_in_file)
    write('\n')
    info('done!')
    write('\n\n')