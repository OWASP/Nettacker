#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import json
import netaddr.ip
import re
from core.ip import getIPRange, IPRange, isIP, isIP6
from core.alert import messages, info
from core._die import __die_failure
from lib.scan.subdomain.engine import __get_subs
from core.log import __log_into_file
import ipaddress
import six

temp = 0


def target_to_host(target):
    """
    convert a target to host, example http://owasp.org to \
        owasp.org or http://127.0.0.1 to 127.0.0.1
    Args:
        target: the target

    Returns:
        the host target
    """
    if target_type(target) == "HTTP":
        target = (
            target.lower()
                .replace("http://", "")
                .replace("https://", "")
                .rsplit("/")[0]
        )
        if ":" in target:
            target = target.rsplit(":")[0]
    return target


def target_type(target):
    """
    define the target type

    Args:
        target: the target

    Returns:
        the target type (SINGLE_IPv4, SINGLE_IPv6, RANGE_IPv4, \
            DOMAIN, HTTP, CIDR_IPv4, UNKNOWN)
    """
    regex = '^([a-zA-Z0-9]+(-|_[a-zA-Z0-9]+)*\.?)+[a-zA-Z]{2,}$'
    targets_protocols = {
        'http': 'HTTP',
        'https': 'HTTP',
        'ftp': 'FTP',
        'ssh': 'SSH',
        'smtp': 'SMTP'
    }

    if isIP(target):
        return "SINGLE_IPv4"
    elif isIP6(target):
        return "SINGLE_IPv6"
    elif True in [target.lower().startswith(key + '://') for key in targets_protocols]:
        scheme = target.split("://")[0].lower()
        return targets_protocols[scheme]
    elif len(target.rsplit(".")) == 7 and "-" in target and "/" not in target:
        start_ip, stop_ip = target.rsplit("-")
        if isIP(start_ip) and isIP(stop_ip):
            return 'RANGE_IPv4'
    elif len(target.rsplit('.')) == 4 and '-' not in target and '/' in target:
        IP, CIDR = target.rsplit('/')
        if isIP(IP) and (int(CIDR) >= 0 and int(CIDR) <= 32):
            return 'CIDR_IPv4'
    elif re.match(regex, target):
        return 'DOMAIN'
    return 'UNKNOWN'


def analysis(
        targets,
        check_ranges,
        check_subdomains,
        subs_temp,
        range_temp,
        log_in_file,
        time_sleep,
        language,
        verbose_level,
        retries,
        socks_proxy,
        enumerate_flag,
):
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
    __log_into_file(range_temp, "a", "", language)
    __log_into_file(subs_temp, "a", "", language)

    for target in targets:
        target = six.ensure_text(target)
        if target_type(target) == "SINGLE_IPv4":
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
        elif target_type(target) == "SINGLE_IPv6":
            yield target

        elif (
                target_type(target) == "RANGE_IPv4"
                or target_type(target) == "CIDR_IPv4"
        ):
            IPs = IPRange(target, range_temp, language)
            global temp
            if target_type(target) == "CIDR_IPv4" and temp == 0:
                net = ipaddress.ip_network(six.text_type(target))
                start = net[0]
                end = net[-1]
                ip1 = int(ipaddress.IPv4Address(six.text_type(start)))
                ip2 = int(ipaddress.IPv4Address(six.text_type(end)))
                yield ip2 - ip1
                temp = 1
                break
            if target_type(target) == "RANGE_IPv4" and temp == 0:
                start, end = target.rsplit("-")
                ip1 = int(ipaddress.IPv4Address(six.text_type(start)))
                ip2 = int(ipaddress.IPv4Address(six.text_type(end)))
                yield ip2 - ip1
                temp = 1
                break
            if not enumerate_flag:
                info(messages(language, "checking").format(target))
            if type(IPs) == netaddr.ip.IPNetwork:
                for IPm in IPs:
                    yield IPm
            elif type(IPs) == list:
                for IPm in IPs:
                    for IP in IPm:
                        yield IP

        elif target_type(target) == "DOMAIN":
            if check_subdomains:
                if check_ranges:
                    if enumerate_flag:
                        info(messages(language, "checking").format(target))
                    sub_domains = (
                        json.loads(open(subs_temp).read())
                        if len(open(subs_temp).read()) > 2
                        else __get_subs(
                            target, 3, "", 0, language, 0, socks_proxy, 3, 0, 0
                        )
                    )
                    if len(open(subs_temp).read()) == 0:
                        __log_into_file(
                            subs_temp, "a", json.dumps(sub_domains), language
                        )
                    if target not in sub_domains:
                        sub_domains.append(target)
                    for target in sub_domains:
                        if not enumerate_flag:
                            info(
                                messages(language, "target_submitted").format(
                                    target
                                )
                            )
                        yield target
                        n = 0
                        err = 0
                        IPs = []
                        while True:
                            try:
                                IPs.append(socket.gethostbyname(target))
                                err = 0
                                n += 1
                                if n == 12:
                                    break
                            except Exception:
                                err += 1
                                if err == 3 or n == 12:
                                    break
                        IPz = list(set(IPs))
                        for IP in IPz:
                            if not enumerate_flag:
                                info(
                                    messages(
                                        language, "checking_range"
                                    ).format(IP)
                                )
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
                    sub_domains = (
                        json.loads(open(subs_temp).read())
                        if len(open(subs_temp).read()) > 2
                        else __get_subs(
                            target, 3, "", 0, language, 0, socks_proxy, 3, 0, 0
                        )
                    )
                    if len(open(subs_temp).read()) == 0:
                        __log_into_file(
                            subs_temp, "a", json.dumps(sub_domains), language
                        )
                    if target not in sub_domains:
                        sub_domains.append(target)
                    for target in sub_domains:
                        if not enumerate_flag:
                            info(
                                messages(language, "target_submitted").format(
                                    target
                                )
                            )
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
                            if n == 12:
                                break
                        except Exception:
                            err += 1
                            if err == 3 or n == 12:
                                break
                    IPz = list(set(IPs))
                    for IP in IPz:
                        if not enumerate_flag:
                            info(
                                messages(language, "checking_range").format(IP)
                            )
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
                        info(
                            messages(language, "target_submitted").format(
                                target
                            )
                        )
                    yield target

        elif target_type(target) == "HTTP":
            if not enumerate_flag:
                info(messages(language, "checking").format(target))
            yield target
            if check_ranges:
                if "http://" == target[:7].lower():
                    target = target[7:].rsplit("/")[0]
                if "https://" == target[:8].lower():
                    target = target[8:].rsplit("/")[0]
                yield target
                IPs = []
                while True:
                    try:
                        IPs.append(socket.gethostbyname(target))
                        err = 0
                        n += 1
                        if n == 12:
                            break
                    except Exception:
                        err += 1
                        if err == 3 or n == 12:
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
