#!/usr/bin/env python
# -*- coding: utf-8 -*-
import netaddr
import time
import sys
import requests
from core.alert import *
from core.compatible import version
from netaddr import iprange_to_cidrs
from netaddr import IPNetwork
from core.log import __log_into_file


def getIPRange(IP):
    """
    get IPv4 range from RIPE online database

    Args:
        IP: IP address

    Returns:
        IP Range
    """
    n = 0
    while 1:
        try:
            data = requests.get(
                'http://rest.db.ripe.net/search.json?query-string={0}&flags=no-filtering'.format(IP)).content
            for line in data.rsplit('\n'):
                line = line.rsplit('"')
                for R in line:
                    if R.count('.') is 6 and R.count('-') is 1 and R.count(' ') is 2:
                        return R.replace(' ', '')
        except:
            n += 1
            if n is 3:
                return IP
                break
            time.sleep(0.1)
    return data


def isIP(IP):
    """
    to check a value if its IPv4 address

    Args:
        IP: the value to check if its IPv4

    Returns:
         True if it's IPv4 otherwise False
    """
    IP = str(IP)
    ip_flag = netaddr.valid_ipv4(IP)
    return ip_flag


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
        if len(Range.rsplit('.')) is 7 and '-' in Range and '/' not in Range:
            if len(Range.rsplit('-')) is 2:
                start_ip, stop_ip = Range.rsplit('-')
                if isIP(start_ip) and isIP(stop_ip):
                    return iprange_to_cidrs(start_ip, stop_ip)
                else:
                    return []
            else:
                return []
        elif len(Range.rsplit('.')) is 4 and '-' not in Range and '/' in Range:
            return IPNetwork(Range)
        else:
            return []
    else:
        warn(messages(language, "skip_duplicate_target"))
        return []


def _generate_IPRange(Range):
    """
    IP range to CIDR and IPNetwork type

    Args:
        Range: IP range

    Returns:
        an array with CIDRs
    """
    if len(Range.rsplit('.')) is 7 and '-' in Range and '/' not in Range:
        if len(Range.rsplit('-')) is 2:
            start_ip, stop_ip = Range.rsplit('-')
            if isIP(start_ip) and isIP(stop_ip):
                return iprange_to_cidrs(start_ip, stop_ip)
            else:
                return []
        else:
            return []
    elif len(Range.rsplit('.')) is 4 and '-' not in Range and '/' in Range:
        return IPNetwork(Range)
    else:
        return []


def isIP6(IP):
    """
    to check a value if its IPv6 address

    Args:
        IP: the value to check if its IPv6

    Returns:
         True if it's IPv6 otherwise False
    """
    IP = str(IP)
    ip_flag = netaddr.valid_ipv6(IP)
    return ip_flag
