#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import socks
import time
import json
import threading
import string
import random
import os
import re
import requests
from core.alert import *
from lib.icmp.engine import do_one as do_one_ping
from lib.socks_resolver.engine import getaddrinfo
from core._time import now


def extra_requirements_dict():
    return {
        "subdomain_scan_use_netcraft": ["True"],
        "subdomain_scan_use_dnsdumpster": ["True"],
        "subdomain_scan_use_virustotal": ["True"],
        "subdomain_scan_use_threatcrowd": ["True"],
        "subdomain_scan_use_comodo_crt": ["True"],
        "subdomain_scan_use_ptrarchive": ["True"]

    }


def __sub_append(subs, data):
    for sub in data:
        if sub not in subs:
            subs.append(sub)
    return subs


def __netcraft(target, timeout_sec, log_in_file, time_sleep, language, verbose_level, socks_proxy, retries, headers):
    try:
        from core.targets import target_to_host
        if socks_proxy is not None:
            socks_version = socks.SOCKS5 if socks_proxy.startswith('socks5://') else socks.SOCKS4
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
                socks.set_default_proxy(socks_version, str(socks_proxy.rsplit(':')[0]), int(socks_proxy.rsplit(':')[1]))
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo
        n = 0
        results = ''
        url = 'https://searchdns.netcraft.com/?restriction=site+contains&host=*.{0}' \
              '&lookup=wait..&position=limited'.format(target)

        subs = []
        while '<b>Next page</b></a>' not in results:
            while 1:
                try:
                    results = requests.get(url, headers=headers)
                    break
                except:
                    n += 1
                    if n is 3:
                        break
                        break
            if results.status_code is 200:
                for l in re.compile('<a href="http://toolbar.netcraft.com/site_report\?url=(.*)">').findall(
                        results.content):
                    if target_to_host(l).endswith(target) and target_to_host(l) not in subs:
                        subs.append(target_to_host(l))
            else:
                # warn 403
                break
            try:
                url = 'http://searchdns.netcraft.com' + re.compile('<A href="(.*?)"><b>Next page</b></a>').findall(
                    results.content)[0]
            except:
                break
        return subs
    except:
        return []


def __threatcrowd(target, timeout_sec, log_in_file, time_sleep, language, verbose_level, socks_proxy, retries, headers):
    try:
        if socks_proxy is not None:
            socks_version = socks.SOCKS5 if socks_proxy.startswith('socks5://') else socks.SOCKS4
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
                socks.set_default_proxy(socks_version, str(socks_proxy.rsplit(':')[0]), int(socks_proxy.rsplit(':')[1]))
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo
        n = 0
        url = 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={0}'.format(target)
        subs = []
        while 1:
            try:
                results = requests.get(url, headers=headers, timeout_sec=timeout_sec)
                break
            except:
                n += 1
                if n is 3:
                    break
        if results.status_code is 200:
            try:
                return json.loads(results.content)["subdomains"]
            except:
                pass
        else:
            # warn 403
            pass
        return subs
    except:
        return []


def __dnsdumpster(target, timeout_sec, log_in_file, time_sleep, language, verbose_level, socks_proxy, retries, headers):
    try:
        url = 'https://dnsdumpster.com/'
        s = requests.session()
        req = s.get(url)
        csrf_middleware = re.compile("<input type='hidden' name='csrfmiddlewaretoken' value='(.*?)' />",
                                     re.S).findall(req.content)[0]
        req = s.post(url, cookies={'csrftoken': csrf_middleware},
                     data={'csrfmiddlewaretoken': csrf_middleware, 'targetip': target},
                     headers={'Referer': url})
        subs = []
        if req.status_code is 200:
            for w in req.content.replace('.<', ' ').replace('<', ' ').replace('>', ' ').rsplit():
                if w.endswith(target) and w not in subs:
                    subs.append(w)
        else:
            # warn 403
            pass
        return subs
    except:
        return []


def __comodo_crt(target, timeout_sec, log_in_file, time_sleep, language, verbose_level, socks_proxy, retries, headers):
    try:
        if socks_proxy is not None:
            socks_version = socks.SOCKS5 if socks_proxy.startswith('socks5://') else socks.SOCKS4
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
                socks.set_default_proxy(socks_version, str(socks_proxy.rsplit(':')[0]), int(socks_proxy.rsplit(':')[1]))
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo
        n = 0
        url = 'https://crt.sh/?q=%.{0}'.format(target)
        subs = []
        while 1:
            try:
                results = requests.get(url, headers=headers)
                break
            except:
                n += 1
                if n is 3:
                    break
        if results.status_code is 200:
            try:
                for l in re.compile('<TD>(.*?)</TD>').findall(results.content):
                    if l.endswith(target) and '*' not in l and l not in subs:
                        subs.append(l)
            except:
                pass
        else:
            # warn 403
            pass
        return subs
    except:
        return []


def __virustotal(target, timeout_sec, log_in_file, time_sleep, language, verbose_level, socks_proxy, retries, headers):
    try:
        from core.targets import target_to_host
        if socks_proxy is not None:
            socks_version = socks.SOCKS5 if socks_proxy.startswith('socks5://') else socks.SOCKS4
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
                socks.set_default_proxy(socks_version, str(socks_proxy.rsplit(':')[0]), int(socks_proxy.rsplit(':')[1]))
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo
        n = 0
        url = 'https://www.virustotal.com/en/domain/{0}/information/'.format(target)
        subs = []
        while 1:
            try:
                results = requests.get(url, headers=headers)
                break
            except:
                n += 1
                if n is 3:
                    break
        if results.status_code is 200:
            try:
                for l in re.compile('<div class="enum.*?">.*?<a target="_blank" href=".*?">(.*?)</a>', re.S).findall(
                        results.content):
                    if target_to_host(l.strip()).endswith(target) and target_to_host(l.strip()) not in subs:
                        subs.append(target_to_host(l.strip()))
            except:
                pass
        else:
            # warn 403
            pass
        return subs
    except:
        return []


def __ptrarchive(target, timeout_sec, log_in_file, time_sleep, language, verbose_level, socks_proxy, retries, headers):
    try:
        if socks_proxy is not None:
            socks_version = socks.SOCKS5 if socks_proxy.startswith('socks5://') else socks.SOCKS4
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
                socks.set_default_proxy(socks_version, str(socks_proxy.rsplit(':')[0]), int(socks_proxy.rsplit(':')[1]))
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo
        n = 0
        url = 'http://ptrarchive.com/tools/search2.htm?label={0}&date=ALL'.format(target)
        subs = []
        while 1:
            try:
                results = requests.get(url, headers=headers)
                break
            except:
                n += 1
                if n is 3:
                    break
        if results.status_code is 200:
            for sub in results.content.rsplit():
                if sub.endswith(target) and sub not in subs:
                    subs.append(sub)
        else:
            # warn 403
            pass
        return subs
    except:
        return []


def __get_subs(target, timeout_sec, log_in_file, time_sleep, language, verbose_level, socks_proxy, retries,
               num, total, extra_requirements={
            "subdomain_scan_use_netcraft": ["True"],
            "subdomain_scan_use_dnsdumpster": ["True"],
            "subdomain_scan_use_virustotal": ["True"],
            "subdomain_scan_use_threatcrowd": ["True"],
            "subdomain_scan_use_comodo_crt": ["True"],
            "subdomain_scan_use_ptrarchive": ["True"]

        }, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                          '(KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
        }):
    total_req = 0
    trying = 0
    for key in extra_requirements:
        if extra_requirements[key][0] == 'True':
            total_req += 1
    if extra_requirements['subdomain_scan_use_netcraft'][0] == 'True':
        trying += 1
        if verbose_level is not 0:
            info(messages(language, 113).format(trying, total_req, num, total, target,
                                                '(subdomain_scan - netcraft)'))
        subs = __sub_append([], __netcraft(target, timeout_sec, log_in_file, time_sleep, language, verbose_level,
                                           socks_proxy, retries, headers))
    if extra_requirements['subdomain_scan_use_ptrarchive'][0] == 'True':
        trying += 1
        if verbose_level is not 0:
            info(messages(language, 113).format(trying, total_req, num, total, target, 'subdomain_scan - ptrarchive'))
        subs = __sub_append(subs, __ptrarchive(target, timeout_sec, log_in_file, time_sleep, language, verbose_level,
                                               socks_proxy, retries, headers))
    if extra_requirements['subdomain_scan_use_threatcrowd'][0] == 'True':
        trying += 1
        if verbose_level is not 0:
            info(
                messages(language, 113).format(trying, total_req, num, total, target, 'subdomain_scan - threatcrowd'))
        subs = __sub_append(subs, __threatcrowd(target, timeout_sec, log_in_file, time_sleep, language, verbose_level,
                                                socks_proxy, retries, headers))
    if extra_requirements['subdomain_scan_use_virustotal'][0] == 'True':
        trying += 1
        if verbose_level is not 0:
            info(messages(language, 113).format(trying, total_req, num, total, target, 'subdomain_scan - virustotal'))
        subs = __sub_append(subs, __virustotal(target, timeout_sec, log_in_file, time_sleep, language, verbose_level,
                                               socks_proxy, retries, headers))
    if extra_requirements['subdomain_scan_use_comodo_crt'][0] == 'True':
        trying += 1
        if verbose_level is not 0:
            info(messages(language, 113).format(trying, total_req, num, total, target, 'subdomain_scan - comodo crt'))
        subs = __sub_append(subs, __comodo_crt(target, timeout_sec, log_in_file, time_sleep, language, verbose_level,
                                               socks_proxy, retries, headers))
    if extra_requirements['subdomain_scan_use_dnsdumpster'][0] == 'True':
        trying += 1
        if verbose_level is not 0:
            info(messages(language, 113).format(trying, total_req, num,
                                                total, target, 'subdomain_scan - dnsdumpster'))
        subs = __sub_append(subs, __dnsdumpster(target, timeout_sec, log_in_file, time_sleep, language, verbose_level,
                                                socks_proxy, retries, headers))
    return subs


def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep,
          language, verbose_level, show_version, check_update, socks_proxy, retries, ping_flag,
          methods_args, scan_id, scan_cmd):  # Main function
    from core.targets import target_type
    from core.targets import target_to_host
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(target) != 'HTTP':
        # requirements check
        new_extra_requirements = extra_requirements_dict()
        if methods_args is not None:
            for extra_requirement in extra_requirements_dict():
                if extra_requirement in methods_args:
                    new_extra_requirements[extra_requirement] = methods_args[extra_requirement]
        extra_requirements = new_extra_requirements
        if target_type(target) == 'HTTP':
            target = target_to_host(target)
        if ping_flag and do_one_ping(target, timeout_sec, 8) is None:
            if socks_proxy is not None:
                socks_version = socks.SOCKS5 if socks_proxy.startswith('socks5://') else socks.SOCKS4
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
                    socks.set_default_proxy(socks_version, str(socks_proxy.rsplit(':')[0]),
                                            int(socks_proxy.rsplit(':')[1]))
                    socket.socket = socks.socksocket
                    socket.getaddrinfo = getaddrinfo
            warn(messages(language, 100).format(target, 'subdomain_scan'))
            return None
        subs = __get_subs(target, timeout_sec, log_in_file, time_sleep, language, verbose_level, socks_proxy, retries,
                          num, total, extra_requirements=extra_requirements)
        info(messages(language, 135).format(len(subs), ', '.join(subs) if len(subs) > 0 else 'None'))
        if len(subs) is not 0:
            save = open(log_in_file, 'a')
            save.write(
                json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': '', 'TYPE': 'subdomain_scan',
                            'DESCRIPTION': messages(language, 135).format(len(subs), ', '.join(subs)
                            if len(subs) > 0 else 'None'), 'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id,
                            'SCAN_CMD': scan_cmd}) + '\n')
            save.close()
        if len(subs) is 0 and verbose_level is not 0:
            save = open(log_in_file, 'a')
            save.write(
                json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': '', 'TYPE': 'subdomain_scan',
                            'DESCRIPTION': messages(language, 135).format(len(subs), ', '.join(subs)
                            if len(subs) > 0 else 'None'), 'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id,
                            'SCAN_CMD': scan_cmd}) + '\n')
            save.close()
        return subs
    else:
        warn(messages(language, 69).format('subdomain_scan', target))
        return []
