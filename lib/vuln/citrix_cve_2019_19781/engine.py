#!/usr/bin/env python
# -*- coding: utf-8 -*-
# citrix_cve_2019_19781_vuln
# https://support.citrix.com/article/CTX267027
# https://www.tripwire.com/state-of-security/vert/citrix-netscaler-cve-2019-19781-what-you-need-to-know/

import socket
import socks
import time
import json
import threading
import string
import random
import sys
import struct
import re
import os
from OpenSSL import crypto
import ssl
from core.alert import *
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from core._time import now
from core.log import __log_into_file
import requests
from lib.payload.wordlists import useragents
from core.decor import socks_proxy, main_function


def extra_requirements_dict():
    return {
        "citrix_cve_2019_19781_vuln_ports": [443]
    }


def citrix_vuln(target, port, timeout_sec, log_in_file, language, time_sleep,
                   thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    try:
        
        from core.conn import connection
        s = connection(target, port, timeout_sec, socks_proxy)

        if not s:
            return False
        else:
            if target_type(target) != "HTTP" and port == 443:
                target = 'https://' + target
            if target_type(target) != "HTTP" and port == 80:
                target = 'http://' + target
            user_agent_list = useragents.useragents()
    
            user_agent = {'User-agent': random.choice(user_agent_list)}
            # as a pre-requisite check that CSS return the word citrix
            req0_url = target+'/vpn/js/rdx/core/css/rdx.css' 
            req0 = requests.get(req0_url, timeout=10, headers=user_agent, verify=False) 
          
            if req0.status_code == 200 and 'citrix' in req0.text.lower():
                info('Citrix appliance detected: ' +target)
                # now check if response code 200 is returned for the following url:
                req_url = target+'/vpn/../vpns/cfg/smb.conf'
                req = requests.get(req_url, timeout=10, headers=user_agent, verify=False)    
    
                if req.status_code == 200 and 'lmhosts' in req.text.lower():  
                    return True
                else:
                    return False
            else:
               return False         
    except Exception as e:
        # some error warning
        return False


def __citrix_vuln(target, port, timeout_sec, log_in_file, language, time_sleep,
                     thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    if citrix_vuln(target, port, timeout_sec, log_in_file, language, time_sleep,
                      thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
        info(messages(language, "target_vulnerable").format(target, port,
                                                            'Citrix CVE-2019-19781 Vulnerability'))
        __log_into_file(thread_tmp_filename, 'w', '0', language)
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'citrix_cve_2019_19781_vuln',
                           'DESCRIPTION': messages(language, "vulnerable").format('citrix_cve_2019_19781_vuln'), 'TIME': now(),
                           'CATEGORY': "vuln",
                           'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
        __log_into_file(log_in_file, 'a', data, language)
        return True
    else:
        return False

@main_function(extra_requirements_dict(), __citrix_vuln, "citrix_cve_2019_19781_vuln", "citrix_cve_2019_19781 not found")
def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    pass