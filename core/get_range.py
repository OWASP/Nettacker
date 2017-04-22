#!/usr/bin/env python

import urllib2
import time

def getIPRange(IP):
    n = 0
    while 1:
        try:
            data = urllib2.urlopen(
                'https://www.utlsapi.com/plugin.php?version=1.1&type=ipv4info&hostname=%s&source=foxext&extversion=2.0.3' % target).read().rsplit(
                'https://www.tcpiputils.com/browse/ip-address/')[1].rsplit('"')[0]
            break
        except:
            n += 1
            if n is 3:
                break
            time.sleep(0.1)