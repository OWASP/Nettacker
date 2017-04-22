#!/usr/bin/env python

import sys


def isIP(IP):
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

def IPRange(Range):
    if len(Range.rsplit('.')) is 7 and '-' in Range and '/' not in Range:
        if len(Range.rsplit('-')) is 2:
            start_ip,stop_ip = Range.rsplit('-')
            if isIP(start_ip) is True and isIP(stop_ip) is True:
                try:
                    from netaddr import iprange_to_cidrs
                    return iprange_to_cidrs(start_ip, stop_ip)
                except:
                    sys.exit('pip install -r requirements.txt')
            else:
                return False
        else:
            return False
    elif len(Range.rsplit('.')) is 4 and '-' not in Range and '/' in Range:
        try:
            from netaddr import IPNetwork
            return IPNetwork(Range)
        except:
            sys.exit('pip install -r requirements.txt')
    else:
        return False