#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import socks
import time
import json
import threading
import string
import logging
import random
import os
import re
import requests
from core.load_modules import load_file_path
from core.alert import *
from lib.socks_resolver.engine import getaddrinfo
from core.targets import target_type
from core.targets import target_to_host
from core._time import now
from core.log import __log_into_file
import shodan

def extra_requirements_dict():
    return {
        "shodan_scan": ["True"],
        "status_code": [200, 401, 403]
    }

def __shodan_scan(target, timeout_sec, log_in_file, time_sleep, language, verbose_level, socks_proxy, retries,headers, shodan_api_key):
    try:
        if socks_proxy is not None:
            socks_version = socks.SOCKS5 if socks_proxy.startswith(
                'socks5://') else socks.SOCKS4
            socks_proxy = socks_proxy.rsplit('://')[1]
            if '@' in socks_proxy:
                socks_username = socks_proxy.rsplit(':')[0]
                socks_password = socks_proxy.rsplit(':')[1].rsplit('@')[0]
                socks.set_default_proxy(socks_version, str(socks_proxy.rsplit('@')[1].rsplit(':')[0]),
                                        int(socks_proxy.rsplit(':')[-1]), username=socks_username,
                                        password=socks_password)
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo
            else:
                socks.set_default_proxy(socks_version, str(
                    socks_proxy.rsplit(':')[0]), int(socks_proxy.rsplit(':')[1]))
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo
        testQuery = "apache"
        key = shodan.Shodan(shodan_api_key)
        dnsipresults = ''
        if "/" in target:
            url1 = "https://api.shodan.io/shodan/host/search?key=" + shodan_api_key + '&query="net: ' + target + '"'        
        else:
            url1 = "https://api.shodan.io/shodan/host/search?key=" + shodan_api_key + '&query="hostname: ' + target + '"' 
            dnsip = "https://api.shodan.io/dns/resolve?hostnames=" + target + "&key="+ shodan_api_key       
        try:
            key.search(testQuery)
        except shodan.APIError as error:
            warn(messages(language, "Invalid_shodan_api_key").format(
            error))
            return []
        try:
            req = requests.get(url1)
        except Exception as e:
            warn(messages(language, "input_target_error").format(
            'shodan', target))
            return []
        if not "/" in target:
            dnsipreq = requests.get(dnsip)
            dnsipresults = json.loads(dnsipreq.text)[target]
            if dnsipresults is None:
                dnsipresults = ''
        subs = []
        results = json.loads(req.text)["matches"]
        if results:
            pass
        else:
            url1 = 'https://api.shodan.io/shodan/host/search?key=' + shodan_api_key + '&query=' + '"hostname: ' + dnsipresults + '"'
            req = requests.get(url1) 
            results = json.loads(req.text)["matches"]
        for i in range(len(results)):
            subsearch = []
            subsearch.append(str(results[i]['ip_str']) + ":" + str(results[i]['port']))
            subsearch.append(results[i]['data'][:200])
            try:
                subsearch.append("Country: " + results[i]['location']['country_name'])
            except:
                pass
            try:
                subsearch.append("Org: " + results[i]['org'])
            except:
                pass
            try:
                for j in results[i]['cpe']:
                    subsearch.append(j)
            except:
                pass
            try:
                for j in results[i]["_shodan"]["options"]:
                    if j == "hostname":
                        subsearch.append(results[i]["_shodan"]["options"][j])
            except:
                pass
            try:
                for key in results[int(i)]["vulns"].keys():
                    subsearch.append(key + "&cvss: " + results[int(i)]["vulns"][key]["cvss"])
            except:
                pass
            subs.append("\n".join(subsearch))
        return subs
    except Exception as e:
        logging.exception("message")
        return []

def __shodan(target, timeout_sec, log_in_file, time_sleep, language, verbose_level, socks_proxy, retries,
               num, total, shodan_api_key, extra_requirements=extra_requirements_dict(), headers={
                   'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                   '(KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
                   'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
                   'Accept-Language': 'en-US,en;q=0.9',
                   'Accept-Encoding': 'gzip, deflate, br',
               }):
    total_req = 0
    trying = 0
    threads = []
    for key in extra_requirements:
        if extra_requirements[key][0] == 'True':
            total_req += 1
    if extra_requirements['shodan_scan'][0] == 'True':
        trying += 1
        if verbose_level > 3:
            info(messages(language, "trying_process").format(
                trying, total_req, num, total, target, 'shodan_scan'))
        t = threading.Thread(target= __shodan_scan,
                             args=(target, timeout_sec, log_in_file, time_sleep, language, verbose_level,
                                   socks_proxy, retries, headers, shodan_api_key))
        threads.append(t)
        t.start()
        threads.append(t)
    # wait for threads
    kill_switch = 0
    kill_time = int(
        timeout_sec / 0.1) if int(timeout_sec / 0.1) is not 0 else 1
    while 1:
        time.sleep(0.1)
        kill_switch += 1
        try:
            if threading.activeCount() is 1 or (kill_time is not -1 and kill_switch is kill_time):
                break
        except KeyboardInterrupt:
            break
    result = []
    try:
        result =  __shodan_scan(target, timeout_sec, log_in_file, time_sleep, language, verbose_level, socks_proxy, retries, headers, shodan_api_key)
    except:
        result = []
    return result


def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, shodan_api_key, scan_id, scan_cmd):  # Main function
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(
            target) != 'HTTP' or target_type(target) != 'SINGLE_IPv6':
        # requirements check
        new_extra_requirements = extra_requirements_dict()
        if methods_args is not None:
            for extra_requirement in extra_requirements_dict():
                if extra_requirement in methods_args:
                    new_extra_requirements[
                        extra_requirement] = methods_args[extra_requirement]
        extra_requirements = new_extra_requirements
        if target_type(target) == 'HTTP':
            target = target_to_host(target)
        
        result = __shodan(target, timeout_sec, log_in_file, time_sleep, language, verbose_level, socks_proxy, retries,
                          num, total, shodan_api_key, extra_requirements=extra_requirements)
        count = 0
        if len(result) is 0:
            info(messages(language, "shodan_false"))
        if len(result) is not 0:
            for parts in result:
                if verbose_level > 2:
                    info(messages(language, "shodan_true").format(parts))
                try:
                    data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': '', 'TYPE': 'shodan_scan',
                                    'DESCRIPTION': parts, 'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id,
                                    'SCAN_CMD': scan_cmd}) + "\n"
                    __log_into_file(log_in_file, 'a', data, language)
                    count += 1
                except:
                    pass
        if len(result) is 0 and verbose_level is not 0:
            data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': '', 'TYPE': 'shodan_scan',
                               'DESCRIPTION': messages(language, "subdomain_found").format(len(result), ', '.join(result)
                                                                                           if len(result) > 0 else 'None'), 'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id,
                               'SCAN_CMD': scan_cmd}) + "\n"
            __log_into_file(log_in_file, 'a', data, language)
        return result
    else:
        warn(messages(language, "input_target_error").format(
            'shodan_scan', target))
        return []
