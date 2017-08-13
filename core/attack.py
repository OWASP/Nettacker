#!/usr/bin/env python

from core.alert import *
import sys


def start_attack(target,num,total,scan_method,users,passwds,timeout_sec,thread_number,ports,log_in_file,time_sleep):
    info(str('start attacking ' + str(target) + ', %s of %s ' % (str(num), str(total))))

    # Calling Engines
    # BruteForce Engines
    if scan_method[-6:] == '_brute':
        try:
            start = getattr(
                __import__('lib.brute.%s.engine' % (scan_method.rsplit('_brute')[0]),
                           fromlist=['start']),
                'start')
        except:
            sys.exit(error('this module is not available'))
        start(target,users,passwds,ports,timeout_sec,thread_number,num,total,log_in_file,time_sleep)
    # Scanners Engines
    if scan_method[-5:] == '_scan':
        try:
            start = getattr(
                __import__('lib.scan.%s.engine' % (scan_method.rsplit('_scan')[0]),
                           fromlist=['start']),
                'start')
        except:
            sys.exit(error('this module is not available'))
        start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep)