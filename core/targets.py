#!/usr/bin/env python

import sys
import socket
import os
from core.attack import start_attack
from core.alert import *
from core.ip import *
try:
    import netaddr.ip
except:
    sys.exit(error('pip install -r requirements.txt'))

def target_type(target):
    if isIP(target) is True:
        return 'SINGLE_IPv4'
    elif len(target.rsplit('.')) is 7 and '-' in target and '/' not in target:
        start_ip, stop_ip = target.rsplit('-')
        if isIP(start_ip) is True and isIP(stop_ip) is True:
            return 'RANGE_IPv4'
        else:
            return 'DOMAIN'
    elif len(target.rsplit('.')) is 4 and '-' not in target and '/' in target:
        IP, CIDR = target.rsplit('/')
        if isIP(IP) is True and (int(CIDR) >= 0 and int(CIDR) <= 32):
            return 'CIDR_IPv4'
        else:
            return 'UNKNOW'
    elif '.' in target and '/' not in target:
        return 'DOMAIN'
    else:
        return 'UNKNOW'



def analysis(targets,check_ranges,check_subdomains):

    tmp = open('tmp/ranges', 'w')
    tmp.write('')
    tmp.close()
    tmp = open('tmp/subs_temp', 'w')
    tmp.write('')
    tmp.close()

    for target in targets:
        if target_type(target) == 'SINGLE_IPv4':
            if check_ranges is True:
                info('checking %s range ...'%(target))
                IPs = IPRange(getIPRange(target))
                if type(IPs) == netaddr.ip.IPNetwork:
                    for IPm in IPs:
                        yield IPm
                elif type(IPs) == list:
                    for IPm in IPs:
                        for IP in IPm:
                            yield IP
            else:
                info('checking %s ...' % (target))
                yield target

        elif target_type(target) == 'RANGE_IPv4' or target_type(target) == 'CIDR_IPv4':
            IPs = IPRange(target)
            info('checking %s ...' % (target))
            if type(IPs) == netaddr.ip.IPNetwork:
                for IPm in IPs:
                    yield IPm
            elif type(IPs) == list:
                for IPm in IPs:
                    for IP in IPm:
                        yield IP

        elif target_type(target) == 'DOMAIN':
            if check_subdomains is True:
                if check_ranges is True:
                    info('checking %s ...' % (target))
                    tmp_exec = os.popen('python lib/sublist3r/sublist3r.py -d ' + target + ' -o tmp/subs_temp').read()
                    tmp_exec = list(set(open('tmp/subs_temp','r').read().rsplit()))
                    sub_domains = []
                    for sub in tmp_exec:
                        if 'this.data.stolen.from.PTRarchive.com.' not in sub and '.internal.nsa.gov.' not in sub:
                            sub_domains.append(sub)
                    if target not in sub_domains:
                        sub_domains.append(target)
                    for target in sub_domains:
                        info('checking %s ...' % (target))
                        yield target
                        n = 0
                        err = 0
                        IPs = []
                        while True:
                            try:
                                IPs.append(socket.gethostbyname(target))
                                err = 0
                                n += 1
                                if n is 12:
                                    break
                            except:
                                err += 1
                                if err is 3 or n is 12:
                                    break
                        IPz = list(set(IPs))
                        for IP in IPz:
                            info('checking %s range ...' % (IP))
                            IPs = IPRange(getIPRange(IP))
                            if type(IPs) == netaddr.ip.IPNetwork:
                                for IPm in IPs:
                                    yield IPm
                            elif type(IPs) == list:
                                for IPm in IPs:
                                    for IPn in IPm:
                                        yield IPn
                else:
                    info('checking %s ...' % (target))
                    tmp_exec = os.popen('python lib/sublist3r/sublist3r.py -d ' + target + ' -o tmp/subs_temp').read()
                    tmp_exec = list(set(open('tmp/subs_temp', 'r').read().rsplit()))
                    sub_domains = []
                    for sub in tmp_exec:
                        if 'this.data.stolen.from.PTRarchive.com.' not in sub and '.internal.nsa.gov.' not in sub:
                            sub_domains.append(sub)
                    if target not in sub_domains:
                        sub_domains.append(target)
                    for target in sub_domains:
                        info('checking %s ...' % (target))
                        yield target
            else:
                if check_ranges is True:
                    info('checking %s ...' % (target))
                    yield target
                    n = 0
                    err = 0
                    IPs = []
                    while True:
                        try:
                            IPs.append(socket.gethostbyname(target))
                            err = 0
                            n += 1
                            if n is 12:
                                break
                        except:
                            err += 1
                            if err is 3 or n is 12:
                                break
                    IPz = list(set(IPs))
                    for IP in IPz:
                        info('checking %s range ...' % (IP))
                        IPs = IPRange(getIPRange(IP))
                        if type(IPs) == netaddr.ip.IPNetwork:
                            for IPm in IPs:
                                yield IPm
                        elif type(IPs) == list:
                            for IPm in IPs:
                                for IPn in IPm:
                                    yield IPn
                else:
                    info('checking %s ...' % (target))
                    yield target