#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import netaddr
import requests
# from core.alert import warn, messages
from netaddr import iprange_to_cidrs
from netaddr import IPNetwork


def generate_ip_range(ip_range):
    """
    IP range to CIDR and IPNetwork type

    Args:
        ip_range: IP range

    Returns:
        an array with CIDRs
    """
    if '/' in ip_range:
        return [
            ip.format() for ip in [cidr for cidr in IPNetwork(ip_range)]
        ]
    else:
        ips = []
        for generator_ip_range in [cidr.iter_hosts() for cidr in iprange_to_cidrs(*ip_range.rsplit('-'))]:
            for ip in generator_ip_range:
                ips.append(ip.format())
        return ips


def get_ip_range(ip):
    """
    get IPv4 range from RIPE online database

    Args:
        ip: IP address

    Returns:
        IP Range
    """
    try:
        return generate_ip_range(
            json.loads(
                requests.get(
                    'https://rest.db.ripe.net/search.json?query-string={ip}&flags=no-filtering'.format(ip=ip)
                ).content
            )['objects']['object'][0]['primary-key']['attribute'][0]['value'].replace(' ', '')
        )
    except Exception:
        return [ip]


def is_ipv4(ip):
    """
    to check a value if its IPv4 address

    Args:
        ip: the value to check if its IPv4

    Returns:
         True if it's IPv4 otherwise False
    """
    return netaddr.valid_ipv4(str(ip))


def IPRange(Range, range_temp, language):
    """
    IP range string to IPNetwork type

    Args:
        Range: IP range string
        range_temp: range_temp filename
        language: language

    Returns:
        an array of IP range in IPNetwork type
    """
    myranges_now = open(range_temp).read().rsplit()
    if Range not in myranges_now:
        __log_into_file(range_temp, 'a', Range + '\n', language)
        if len(Range.rsplit('.')) == 7 and '-' in Range and '/' not in Range:
            if len(Range.rsplit('-')) == 2:
                start_ip, stop_ip = Range.rsplit('-')
                if isIP(start_ip) and isIP(stop_ip):
                    return iprange_to_cidrs(start_ip, stop_ip)
                else:
                    return []
            else:
                return []
        elif len(Range.rsplit('.')) == 4 and '-' not in Range and '/' in Range:
            return IPNetwork(Range)
        else:
            return []
    else:
        warn(messages("skip_duplicate_target"))
        return []


def is_ipv6(ip):
    """
    to check a value if its IPv6 address

    Args:
        ip: the value to check if its IPv6

    Returns:
         True if it's IPv6 otherwise False
    """
    return netaddr.valid_ipv6(str(ip))
