#!/usr/bin/env python

from optparse import OptionGroup
from optparse import OptionParser
from core.targets import analysis
from core.attack import start_attack
from core.alert import *

def load():
    write('\n\n')
    info('Nettacker engine started ...')

    # module_names = ['smtp_brute', 'ftp_brute', 'rdp_brute', 'ssh_brute', 'http_brute', 'mysql_brute', 'mssql_brute']
    module_names = ['smtp_brute','port_scan','ftp_brute','ssh_brute']

    parser = OptionParser(usage='python nettacker.py [options]', description='Nettacker Help Menu',
                          epilog='Please read license and agreements https://github.com/Nettacker/Nettacker')

    parser.add_option('-r', '--range', action='store_true', default=False, dest='check_ranges',
                      help='scan all IPs in range')
    parser.add_option('-s', '--sub-domains', action='store_true', default=False, dest='check_subdomains',
                      help='find and scan subdomains')
    parser.add_option('-t', '--threads', action='store', default=5, type='int', dest='thread_number',
                      help='thread numbers')
    parser.add_option('-L', '--logs', action='store_true', default=False,  dest='log_in_file',
                      help='save all logs in file (logs.txt)')

    # Target Options
    target = OptionGroup(parser, "Target", "Target input options")
    target.add_option('-i', '--targets', action='store', dest='targets', default=None,
                      help='target(s) list, separate with ","')
    target.add_option('-l', '--targets-list', action='store', dest='targets_list', default=None,
                      help='read target(s) from file')
    parser.add_option_group(target)

    # Methods Options
    method = OptionGroup(parser, "Method", "Scan method options")
    method.add_option('-a', '--automatic', action='store_true', default=False, dest='auto_scan',
                      help='automatically scan every services')
    method.add_option('-m', '--method', action='store',
                      dest='scan_method', default=None,
                      help='choose scan method %s' % (module_names))
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
                      dest='ports', default=None,
                      help='port(s) list, separate with ","')
    method.add_option('-T', '--timeout', action='store',
                      dest='timeout_sec', default=0.5, type='float',
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
    auto_scan = options.auto_scan
    scan_method = options.scan_method
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
    if timeout_sec >= 15:
        warn('set timeout to %s seconds, it is too big, isn\'t it ? by the way we are continuing...')
    if auto_scan is True and scan_method is not None:
        sys.exit(error('please use specify method or automatic option, you can\'t using both!'))
    if scan_method is not None and scan_method not in module_names:
        sys.exit(error('this scan module [%s] not found!'%(scan_method)))
    if scan_method is None:
        sys.exit(error('please choose your scan method!'))
    if auto_scan is True:
        sys.exit(error('this module is not ready to use in this version, please choose your scan method'))
    if ports is None and scan_method is not None and (scan_method[-6:] == '_brute' or scan_method[-5:] == '_scan'):
        sys.exit(error('this module required port(s) (list) to bruteforce/scan!'))
    else:
        if '-' in ports:
            ports = ports.rsplit('-')
            ports = range(int(ports[0]), int(ports[1]) + 1)
        else:
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
    total_targets = analysis(targets, check_ranges, check_subdomains)
    targets = open('tmp/tmp_targets')
    n = 0
    for target in targets:
        n+=1
        start_attack(target.rsplit()[0],n,total_targets,scan_method,users,passwds,timeout_sec,thread_number,ports)
    write('\n')
    info('done!')
    write('\n\n')