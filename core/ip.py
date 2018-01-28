#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import sys
import requests
from core.alert import *
from core.compatible import version
from netaddr import iprange_to_cidrs
from netaddr import IPNetwork


def getIPRange(IP):
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
    IP = str(IP)
    if len(IP.rsplit('.')) is 4 and '-' not in IP and '/' not in IP:
        ip_flag = True
        for num in IP.rsplit('.'):
            try:
                if int(num) <= 255:
                    pass
                else:
                    ip_flag = False
            except:
                ip_flag = False
        return ip_flag
    return False


def IPRange(Range, range_temp, language):
    myranges_now = open(range_temp).read().rsplit()
    if Range not in myranges_now:
        r_f = open(range_temp, 'a')
        r_f.write(Range + '\n')
        r_f.close()
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
        warn(messages(language, 49))
        return []


def _generate_IPRange(Range):
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
