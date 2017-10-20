#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import os
from core.ip import *
from core.alert import *

try:
    import netaddr.ip
except:
    error('pip install -r requirements.txt')
    sys.exit(1)


def target_to_host(target):
    if target_type(target) == 'HTTP':
        target = target.lower().replace('http://', '').replace('https://', '').rsplit('/')[0]
        if ':' in target:
            target = target.rsplit(':')[0]
    return target


def target_type(target):
    if isIP(target) is True:
        return 'SINGLE_IPv4'
    elif len(target.rsplit('.')) is 7 and '-' in target and '/' not in target:
        start_ip, stop_ip = target.rsplit('-')
        if isIP(start_ip) is True and isIP(stop_ip) is True:
            return 'RANGE_IPv4'
        else:
            return 'DOMAIN'
    elif target.lower().startswith('http://') or target.lower().startswith('https://'):
        return 'HTTP'
    elif len(target.rsplit('.')) is 4 and '-' not in target and '/' in target:
        IP, CIDR = target.rsplit('/')
        if isIP(IP) is True and (int(CIDR) >= 0 and int(CIDR) <= 32):
            return 'CIDR_IPv4'
    elif '.' in target and '/' not in target:
        return 'DOMAIN'
    else:
        return 'UNKNOW'


def analysis(targets, check_ranges, check_subdomains, subs_temp, range_temp, log_in_file, time_sleep,
             language, verbose_level, show_version, check_update, proxies, retries):
    tmp = open(range_temp, 'w')
    tmp.write('')
    tmp.close()
    tmp = open(subs_temp, 'w')
    tmp.write('')
    tmp.close()

    for target in targets:
        if target_type(target) == 'SINGLE_IPv4':
            if check_ranges is True:
                info(messages(language, 51).format(target))
                IPs = IPRange(getIPRange(target), range_temp, language)
                if type(IPs) == netaddr.ip.IPNetwork:
                    for IPm in IPs:
                        yield IPm
                elif type(IPs) == list:
                    for IPm in IPs:
                        for IP in IPm:
                            yield IP
            else:
                info(messages(language, 81).format(target))
                yield target

        elif target_type(target) == 'RANGE_IPv4' or target_type(target) == 'CIDR_IPv4':
            IPs = IPRange(target, range_temp, language)
            info(messages(language, 52).format(target))
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
                    info(messages(language, 52).format(target))
                    tmp_exec = os.popen(
                        'python lib/sublist3r/sublist3r.py -d {0} -o {1} '.format(target, subs_temp)).read()
                    tmp_exec = list(set(open(subs_temp, 'r').read().replace(' ', '').rsplit()))
                    sub_domains = []
                    for sub in tmp_exec:
                        if 'PTRarchive.com' not in sub and '.internal.nsa.gov.' not in sub \
                                and 'Sublist3r' not in sub and sub not in sub_domains:
                            sub_domains.append(sub)
                    if target not in sub_domains:
                        sub_domains.append(target)
                    for target in sub_domains:
                        info(messages(language, 81).format(target))
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
                            info(messages(language, 51).format(IP))
                            IPs = IPRange(getIPRange(IP), range_temp, language)
                            if type(IPs) == netaddr.ip.IPNetwork:
                                for IPm in IPs:
                                    yield IPm
                            elif type(IPs) == list:
                                for IPm in IPs:
                                    for IPn in IPm:
                                        yield IPn
                else:
                    info(messages(language, 52).format(target))
                    tmp_exec = os.popen(
                        'python lib/sublist3r/sublist3r.py -d {0} -o {1} '.format(target, subs_temp)).read()
                    tmp_exec = list(set(open(subs_temp, 'r').read().replace(' ', '').rsplit()))
                    sub_domains = []
                    for sub in tmp_exec:
                        if 'PTRarchive.com' not in sub and '.internal.nsa.gov.' not in sub \
                                and 'Sublist3r' not in sub and sub not in sub_domains:
                            sub_domains.append(sub)
                    if target not in sub_domains:
                        sub_domains.append(target)
                    for target in sub_domains:
                        info(messages(language, 81).format(target))
                        yield target
            else:
                if check_ranges is True:
                    info(messages(language, 52).format(target))
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
                        info(messages(language, 51).format(IP))
                        IPs = IPRange(getIPRange(IP), range_temp, language)
                        if type(IPs) == netaddr.ip.IPNetwork:
                            for IPm in IPs:
                                yield IPm
                        elif type(IPs) == list:
                            for IPm in IPs:
                                for IPn in IPm:
                                    yield IPn
                else:
                    info(messages(language, 81).format(target))
                    yield target

        elif target_type(target) == 'HTTP':
            info(messages(language, 52).format(target))
            yield target
            if check_ranges is True:
                if 'http://' == target[:7].lower():
                    target = target[7:].rsplit('/')[0]
                if 'https://' == target[:8].lower():
                    target = target[8:].rsplit('/')[0]
                yield target
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
                    info(messages(language, 51).format(IP))
                    IPs = IPRange(getIPRange(IP), range_temp, language)
                    if type(IPs) == netaddr.ip.IPNetwork:
                        for IPm in IPs:
                            yield IPm
                    elif type(IPs) == list:
                        for IPm in IPs:
                            for IPn in IPm:
                                yield IPn

        else:
            sys.exit(error(messages(language, 50).format(target)))
