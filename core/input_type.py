#!/usr/bin/env python

from core.ip import isIP

def load(targets):
    target_list = {}
    for target in targets:
        target = target.rsplit()[0]
        if isIP(target) is True:
            target_list[target] =  'SINGLE_IPv4'
        elif len(target.rsplit('.')) is 7 and '-' in target and '/' not in target:
            start_ip,stop_ip = target.rsplit('-')
            if isIP(start_ip) is True and isIP(stop_ip) is True:
                target_list[target] = 'RANGE_IPv4'
            else:
                target_list[target] = 'DOMAIN'
        elif len(target.rsplit('.')) is 4 and '-' not in target and '/' in target:
            IP,CIDR = target.rsplit('/')
            if isIP(IP) is True and (int(CIDR) >= 0 and int(CIDR) <= 32):
                target_list[target] = 'CIDR_IPv4'
            else:
                target_list[target] = 'UNKNOW'
        elif '.' in target and '/' not in target:
            target_list[target] = 'DOMAIN'
        else:
            target_list[target] = 'UNKNOW'
    return target_list
