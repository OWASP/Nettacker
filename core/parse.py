#!/usr/bin/env python

from optparse import OptionGroup
from optparse import OptionParser
from core.targets import analysis
from core.attack import start_attack
from core.alert import *

def load():

    info('Nettacker engine started ...')

    module_names = ['smtp_brute', 'ftp_brute', 'rdp_brute', 'ssh_brute', 'http_brute', 'mysql_brute', 'mssql_brute']

    parser = OptionParser(usage='python nettacker.py [options]', description='Nettacker Help Menu',
                          epilog='Please read license and agreements https://github.com/Nettacker/Nettacker')

    parser.add_option('-r', '--range', action='store_true', default=False, dest='check_ranges',
                      help='scan all IPs in range')
    parser.add_option('-s', '--sub-domains', action='store_true', default=False, dest='check_subdomains',
                      help='find and scan subdomains')
    parser.add_option('-t', '--threads', action='store', default=5, type='int', dest='thread_number',
                      help='thread numbers')

    # Target Options
    target = OptionGroup(parser, "Target", "Target input options")
    target.add_option('-u', '--targets', action='store', dest='targets', default=None,
                      help='target(s) list, separate with ","')
    target.add_option('-l', '--list', action='store', dest='targets_list', default=None,
                      help='read target(s) from file')
    parser.add_option_group(target)

    # Methods Options
    method = OptionGroup(parser, "Method", "Scan method options")
    method.add_option('-a', '--automatic', action='store_true', default=False, dest='auto_scan',
                      help='automatically scan every services')
    method.add_option('-m', '--method', action='store',
                      dest='scan_method', default=None,
                      help='choose scan method %s' % (module_names))
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

    if targets is None and targets_list is None:
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

    if auto_scan is True and scan_method is not None:
        sys.exit(error('please use specify method or automatic option, you can\'t using both!'))
    if scan_method is not None and scan_method not in module_names:
        sys.exit(error('this scan module [%s] not found!'%(scan_method)))
    if auto_scan is True:
        sys.exit(error('this module is not ready to use in this version, please choose your scan method'))
    total_targets = analysis(targets, check_ranges, check_subdomains)
    targets = open('tmp/tmp_targets')
    n = 0
    for target in targets:
        n+=1
        start_attack(target.rsplit()[0],n,total_targets,scan_method)
