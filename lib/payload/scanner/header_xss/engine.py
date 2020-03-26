#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author: Pradeep Jairamani , github.com/pradeepjairamani

import requests

def header_xss(host, data=None, payloads_xss=None, headers_xss=None):
    '''
    Args:
        host: The Hostname to check
        payload_xss: XSS Payload
        header_xss : Headers for XSS
    Return
        Result : True or False
    '''
    if data is None:
        data = {'a': '1'}
    if payloads_xss is None:
        payloads_xss = r'<script>alert()</script>'
    if headers_xss is None:
        headers_xss = {
                'User-Agent'        : payloads_xss,
                'Except'            : payloads_xss,
                'Cookie'            : payloads_xss,
                'Origin'            : payloads_xss,
                'Referer'           : payloads_xss,
                'Accept-Encoding'   : payloads_xss,
                'Accept-Language'   : payloads_xss,
                'Accept'            : payloads_xss,
                'X-Forwaded-For'    : payloads_xss
            }
    try:
        # Expanding our scope of attack by using all the
        # HTTP methods available, HEAD and OPTIONS return
        # header sets only, so rXSS is null in those cases.
        r1 = requests.get(host, headers=headers_xss)
        r2 = requests.post(host, data=data, headers=headers_xss)
        r3 = requests.put(host, data=data, headers=headers_xss)
        r4 = requests.delete(host, headers=headers_xss)
        req = [r1, r2, r3, r4]
        for r in req:
            if payloads_xss.lower() in r.text.lower():
                return True
        return False
    except Exception:
        return False
