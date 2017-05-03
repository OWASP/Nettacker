#!/usr/bin/env python

from core.alert import *

def start_attack(target,num,total,scan_method,users,passwds,timeout_sec,thread_number,ports):
    info(str('start attacking ' + str(target) + ', %s of %s ' % (str(num), str(total))))
    if scan_method[-6:] == '_brute':
        start = getattr(
            __import__('lib.brute.%s.engine' % (scan_method.rsplit('_brute')[0]),
                       fromlist=['start']),
            'start')
        start(target,users,passwds,ports,timeout_sec,thread_number,num,total)
    if scan_method[-5:] == '_scan':
        start = getattr(
            __import__('lib.scan.%s.engine' % (scan_method.rsplit('_scan')[0]),
                       fromlist=['start']),
            'start')
        start(target, ports, timeout_sec, thread_number, num, total)