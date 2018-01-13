#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import json
from core.ip import *
from core.alert import *
from lib.scan.subdomain.engine import __get_subs

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
             language, verbose_level, show_version, check_update, proxies, retries, socks_proxy, enumerate_flag):
    tmp = open(range_temp, 'a')
    tmp.write('')
    tmp.close()
    tmp = open(subs_temp, 'a')
    tmp.write('')
    tmp.close()

    for target in targets:
        if target_type(target) == 'SINGLE_IPv4':
            if check_ranges is True:
                if not enumerate_flag: info(messages(language, 51).format(target))
                IPs = IPRange(getIPRange(target), range_temp, language)
                if type(IPs) == netaddr.ip.IPNetwork:
                    for IPm in IPs:
                        yield IPm
                elif type(IPs) == list:
                    for IPm in IPs:
                        for IP in IPm:
                            yield IP
            else:
                if not enumerate_flag: info(messages(language, 81).format(target))
                yield target

        elif target_type(target) == 'RANGE_IPv4' or target_type(target) == 'CIDR_IPv4':
            IPs = IPRange(target, range_temp, language)
            if not enumerate_flag: info(messages(language, 52).format(target))
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
                    if enumerate_flag: info(messages(language, 52).format(target))
                    sub_domains = json.loads(open(subs_temp).read()) if len(open(subs_temp).read()) > 0 else \
                        __get_subs(target, 3, '', 0, language, 0, socks_proxy, 3, 0, 0)
                    if len(open(subs_temp).read()) is 0:
                        f = open(subs_temp, 'a')
                        f.write(json.dumps(sub_domains))
                        f.close()
                    if target not in sub_domains:
                        sub_domains.append(target)
                    for target in sub_domains:
                        if not enumerate_flag: info(messages(language, 81).format(target))
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
                            if not enumerate_flag: info(messages(language, 51).format(IP))
                            IPs = IPRange(getIPRange(IP), range_temp, language)
                            if type(IPs) == netaddr.ip.IPNetwork:
                                for IPm in IPs:
                                    yield IPm
                            elif type(IPs) == list:
                                for IPm in IPs:
                                    for IPn in IPm:
                                        yield IPn
                else:
                    if enumerate_flag: info(messages(language, 52).format(target))
                    sub_domains = json.loads(open(subs_temp).read()) if len(open(subs_temp).read()) > 0 else \
                        __get_subs(target, 3, '', 0, language, 0, socks_proxy, 3, 0, 0)
                    if len(open(subs_temp).read()) is 0:
                        f = open(subs_temp, 'a')
                        f.write(json.dumps(sub_domains))
                        f.close()
                    if target not in sub_domains:
                        sub_domains.append(target)
                    for target in sub_domains:
                        if not enumerate_flag: info(messages(language, 81).format(target))
                        yield target
            else:
                if check_ranges is True:
                    if not enumerate_flag: info(messages(language, 52).format(target))
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
                        if not enumerate_flag: info(messages(language, 51).format(IP))
                        IPs = IPRange(getIPRange(IP), range_temp, language)
                        if type(IPs) == netaddr.ip.IPNetwork:
                            for IPm in IPs:
                                yield IPm
                        elif type(IPs) == list:
                            for IPm in IPs:
                                for IPn in IPm:
                                    yield IPn
                else:
                    if not enumerate_flag: info(messages(language, 81).format(target))
                    yield target

        elif target_type(target) == 'HTTP':
            if not enumerate_flag: info(messages(language, 52).format(target))
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
                    if not enumerate_flag: info(messages(language, 51).format(IP))
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
