#!/usr/bin/env python
import urllib2
import time
import sys
from core.alert import *
try:
    from netaddr import iprange_to_cidrs
    from netaddr import IPNetwork
except:
    sys.exit(error('pip install -r requirements.txt'))


def getIPRange(IP):
    n = 0
    while 1:
        try:
            data = urllib2.urlopen(
                'https://whois.arin.net/rest/nets;q=%s?showDetails=true&showARIN=false&showNonArinTopLevelNet=false&ext=netref2' % IP).read()
            data = data.rsplit('<startAddress>')[1].rsplit('</startAddress>')[0] + '-' + data.rsplit('<endAddress>')[1].rsplit('</endAddress>')[0]
            break
        except:
            n += 1
            if n is 3:
                return IP
                break
            time.sleep(0.1)
    return data



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
    myranges_now = open('tmp/ranges').read().rsplit()
    if Range not in myranges_now:
        r_f = open('tmp/ranges','a')
        r_f.write(Range+'\n')
        r_f.close()
        if len(Range.rsplit('.')) is 7 and '-' in Range and '/' not in Range:
            if len(Range.rsplit('-')) is 2:
                start_ip,stop_ip = Range.rsplit('-')
                if isIP(start_ip) is True and isIP(stop_ip) is True:
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
        warn('skip duplicate target (some subdomains/domains may have same IP and Ranges)')
        return []
