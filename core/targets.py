#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import json
import netaddr.ip
import re
from core.ip import *
from core.alert import *
from core._die import __die_failure
from lib.scan.subdomain.engine import __get_subs
from core.log import __log_into_file


def target_to_host(target):
    """
    convert a target to host, example http://owasp.org to owasp.org or http://127.0.0.1 to 127.0.0.1
    Args:
        target: the target

    Returns:
        the host target
    """
    if target_type(target) == 'HTTP':
        target = target.lower().replace(
            'http://', '').replace('https://', '').rsplit('/')[0]
        if ':' in target:
            target = target.rsplit(':')[0]
    return target


def target_type(target):
    """
    define the target type

    Args:
        target: the target

    Returns:
        the target type (SINGLE_IPv4, SINGLE_IPv6, RANGE_IPv4, DOMAIN, HTTP, CIDR_IPv4, UNKNOWN)
    """
    if isIP(target):
        return 'SINGLE_IPv4'
    elif isIP6(target):
        return 'SINGLE_IPv6'
    elif len(target.rsplit('.')) is 7 and '-' in target and '/' not in target:
        start_ip, stop_ip = target.rsplit('-')
        if isIP(start_ip) and isIP(stop_ip):
            return 'RANGE_IPv4'
    elif re.match('^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$', target):
        return 'DOMAIN'
    elif (target.lower().startswith('http://') or target.lower().startswith('https://')):
        t = target.rsplit("://")[1].rsplit("/")[0].rsplit(":")[0]
        if isIP(t) or isIP6(t) or re.match('^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$', t):
            return 'HTTP'
    elif len(target.rsplit('.')) is 4 and '-' not in target and '/' in target:
        IP, CIDR = target.rsplit('/')
        if isIP(IP) and (int(CIDR) >= 0 and int(CIDR) <= 32):
            return 'CIDR_IPv4'
    return 'UNKNOWN'


def analysis(targets, check_ranges, check_subdomains, subs_temp, range_temp, log_in_file, time_sleep,
             language, verbose_level, retries, socks_proxy, enumerate_flag):
    """
    analysis and calulcate targets.

    Args:
        targets: targets
        check_ranges: check IP range flag
        check_subdomains: check subdomain flag
        subs_temp: subdomain temp filename
        range_temp: IP range tmp filename
        log_in_file: output filename
        time_sleep: time to sleep
        language: language
        verbose_level: verbose level number
        retries: retries number
        socks_proxy: socks proxy
        enumerate_flag: enumerate flag

    Returns:
        a generator
    """
    __log_into_file(range_temp, 'a', '', language)
    __log_into_file(subs_temp, 'a', '', language)

    for target in targets:
        if target_type(target) == 'SINGLE_IPv4':
            if check_ranges:
                if not enumerate_flag:
                    info(messages(language, "checking_range").format(target))
                IPs = IPRange(getIPRange(target), range_temp, language)
                if type(IPs) == netaddr.ip.IPNetwork:
                    for IPm in IPs:
                        yield IPm
                elif type(IPs) == list:
                    for IPm in IPs:
                        for IP in IPm:
                            yield IP
            else:
                if not enumerate_flag:
                    info(messages(language, "target_submitted").format(target))
                yield target
        elif target_type(target) == 'SINGLE_IPv6':
            yield target

        elif target_type(target) == 'RANGE_IPv4' or target_type(target) == 'CIDR_IPv4':
            IPs = IPRange(target, range_temp, language)
            if not enumerate_flag:
                info(messages(language, "checking").format(target))
            if type(IPs) == netaddr.ip.IPNetwork:
                for IPm in IPs:
                    yield IPm
            elif type(IPs) == list:
                for IPm in IPs:
                    for IP in IPm:
                        yield IP

        elif target_type(target) == 'DOMAIN':
            if check_subdomains:
                if check_ranges:
                    if enumerate_flag:
                        info(messages(language, "checking").format(target))
                    sub_domains = json.loads(open(subs_temp).read()) if len(open(subs_temp).read()) > 2 else \
                        __get_subs(target, 3, '', 0, language,
                                   0, socks_proxy, 3, 0, 0)
                    if len(open(subs_temp).read()) is 0:
                        __log_into_file(subs_temp, 'a', json.dumps(
                            sub_domains), language)
                    if target not in sub_domains:
                        sub_domains.append(target)
                    for target in sub_domains:
                        if not enumerate_flag:
                            info(messages(language, "target_submitted").format(target))
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
                            if not enumerate_flag:
                                info(messages(language, "checking_range").format(IP))
                            IPs = IPRange(getIPRange(IP), range_temp, language)
                            if type(IPs) == netaddr.ip.IPNetwork:
                                for IPm in IPs:
                                    yield IPm
                            elif type(IPs) == list:
                                for IPm in IPs:
                                    for IPn in IPm:
                                        yield IPn
                else:
                    if enumerate_flag:
                        info(messages(language, "checking").format(target))
                    sub_domains = json.loads(open(subs_temp).read()) if len(open(subs_temp).read()) > 2 else \
                        __get_subs(target, 3, '', 0, language,
                                   0, socks_proxy, 3, 0, 0)
                    if len(open(subs_temp).read()) is 0:
                        __log_into_file(subs_temp, 'a', json.dumps(
                            sub_domains), language)
                    if target not in sub_domains:
                        sub_domains.append(target)
                    for target in sub_domains:
                        if not enumerate_flag:
                            info(messages(language, "target_submitted").format(target))
                        yield target
            else:
                if check_ranges:
                    if not enumerate_flag:
                        info(messages(language, "checking").format(target))
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
                        if not enumerate_flag:
                            info(messages(language, "checking_range").format(IP))
                        IPs = IPRange(getIPRange(IP), range_temp, language)
                        if type(IPs) == netaddr.ip.IPNetwork:
                            for IPm in IPs:
                                yield IPm
                        elif type(IPs) == list:
                            for IPm in IPs:
                                for IPn in IPm:
                                    yield IPn
                else:
                    if not enumerate_flag:
                        info(messages(language, "target_submitted").format(target))
                    yield target

        elif target_type(target) == 'HTTP':
            if not enumerate_flag:
                info(messages(language, "checking").format(target))
            yield target
            if check_ranges:
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
                    if not enumerate_flag:
                        info(messages(language, "checking_range").format(IP))
                    IPs = IPRange(getIPRange(IP), range_temp, language)
                    if type(IPs) == netaddr.ip.IPNetwork:
                        for IPm in IPs:
                            yield IPm
                    elif type(IPs) == list:
                        for IPm in IPs:
                            for IPn in IPm:
                                yield IPn

        else:
            __die_failure(messages(language, "unknown_target").format(target))
