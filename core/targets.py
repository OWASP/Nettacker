#!/usr/bin/env python

from core.ip import IPRange
from core.get_range import getIPRange
from core.attack import start_attack
import os
import sys
import socket

def log_it(target):
    f = open('tmp_target', 'a')
    f.write(target + '\n')
    f.close()

def scan_check(target):
    scan_flag = True
    targets = open('tmp_target')
    for t in targets:
        if target == t.rsplit()[0]:
            scan_flag = False
    targets.close()
    return scan_flag

def attack_ip(IP):
    IPs = IPRange(getIPRange(IP))
    if len(IPs) is 1:
        for IP in IPs:
            scan_flag = scan_check(IP)
            if scan_flag is True:
                log_it(IP)
                start_attack(IP, False)
    else:
        for IPR in IPs:
            for IP in IPR:
                scan_flag = scan_check(IP)
                if scan_flag is True:
                    log_it(IP)
                    start_attack(IP, False)

def attack(target,range_flag,isDomain=False):
    if range_flag is False:
        scan_flag = scan_check(target)
        log_it(target)
        if scan_flag is True:
            if isDomain is True:
                getip_flag = True
                try:
                    IP = socket.gethostbyname(target)
                except:
                    getip_flag = False
                    pass
                if getip_flag is True:
                    pass
                    start_attack(target,isDomain)
            else:
                start_attack(target, isDomain)
    else:
        if isDomain is True:
            scan_flag = scan_check(target)
            if scan_flag is True:
                log_it(target)
            try:
                IP = socket.gethostbyname(target)
                start_attack(target, isDomain)
                attack_ip(IP)
            except:
                pass
        else:
            attack_ip(target)

def analysis(targets):
    range_flag = True if (sys.argv[2] == '--range' or sys.argv[2] == '-r') else False
    tmp = open('tmp_target', 'w')
    tmp.write('')
    tmp.close()
    for target in targets:
        if targets[target] == 'SINGLE_IPv4':
            attack(target,range_flag)
        elif targets[target] == 'RANGE_IPv4' or targets[target] == 'CIDR_IPv4':
            IPs = IPRange(target)
            if len(IPs) is 1:
                for IP in IPs:
                    attack(IP, range_flag)
            else:
                for IPR in IPs:
                    for IP in IPR:
                        attack(IP, range_flag)
        elif targets[target] == 'DOMAIN':
            print 'finding subdomains ...'
            tmp = open('tmp', 'w')
            tmp.write('')
            tmp.close()
            tmp = os.popen('lib\\sublist3r\\sublist3r.py -d ' + target + ' -o tmp').read()
            subs = open('tmp').read().rsplit()
            for sub in subs:
                attack(sub, range_flag,True)
        else:
            pass
    return 0