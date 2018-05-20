#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Pradeep Jairamani , github.com/pradeepjairamani
# Service Scanner (Product and Version Detection)

from core.targets import target_type
import requests
import socket

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def discover(host, port):
    if port==80 or port==443:
        if port == 80:
            host = "http://" + host
        else:
            host = "https://" + host
        r = requests.get(host, verify = False)
        try:
            return "Server: " + r.headers['server'] + " Powered by" + r.headers['X-Powered-By']
        except:
            try:
                return r.headers['server']
            except:
                return None
    else:
        if target_type(host) == "SINGLE_IPv6":
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if target_type(host) == "SINGLE_IPv6":
            s.connect((host, port, 0, 0))
        else:
            s.connect((host, port))
            data = s.recv(100)
            #data = data.split()
            return (data)
        s.close()
