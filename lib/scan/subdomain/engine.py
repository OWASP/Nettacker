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
from core.load_modules import load_file_path
from core.alert import *
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.log import __log_into_file


def extra_requirements_dict():
    return {
        "subdomain_scan_use_netcraft": ["True"],
        "subdomain_scan_use_dnsdumpster": ["True"],
        "subdomain_scan_use_virustotal": ["True"],
        "subdomain_scan_use_threatcrowd": ["True"],
        "subdomain_scan_use_comodo_crt": ["True"],
        "subdomain_scan_use_ptrarchive": ["True"],
        "subdomain_scan_use_google_dig": ["True"],
        "subdomain_scan_use_cert_spotter": ["True"],
        "subdomain_scan_time_limit_seconds": ["-1"]

        # Must add later!
        # https://censys.io/certificates?q=domain
        # https://transparencyreport.google.com/https/certificates
        # https://otx.alienvault.com/indicator/domain/google.com

    }


def __sub_append(subs, data):
    for sub in data:
        if sub not in subs:
            subs.append(sub)
    return subs


def __cert_spotter(target, timeout_sec, log_in_file, time_sleep, language, verbose_level, socks_proxy, retries, headers,
                   thread_tmp_filename):
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
        req = requests.get(
            'https://certspotter.com/api/v0/certs?domain={0}'.format(target), headers=headers)
        subs = []
        if req.status_code is 200:
            for w in req.content.replace('"', ' ').replace('\'', ' ').rsplit():
                if '*' not in w and w.endswith('.' + target) and w not in subs:
                    subs.append(w)
        else:
            # warn 403
            pass
        __log_into_file(thread_tmp_filename, 'a', '\n'.join(subs), language)
        return subs
    except:
        return []


def __google_dig(target, timeout_sec, log_in_file, time_sleep, language, verbose_level, socks_proxy, retries, headers,
                 thread_tmp_filename):
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
        url_1 = 'https://toolbox.googleapps.com/apps/dig/#ANY/'
        url_2 = 'https://toolbox.googleapps.com/apps/dig/lookup'
        s = requests.session()
        req = s.get(url_1)
        csrf_middleware = re.compile("<input type='hidden' name='csrfmiddlewaretoken' value='(.*?)' />",
                                     re.S).findall(req.content)[0]
        req = s.post(url_2, cookies={'csrftoken': csrf_middleware},
                     data={'csrfmiddlewaretoken': csrf_middleware,
                           'domain': target, 'typ': 'ANY'},
                     headers={'Referer': url_1})
        subs = []
        if req.status_code is 200:
            for w in json.loads(req.content)["response"].replace('"', ' ').replace(';', ' ').rsplit():
                if '*' not in w and w.endswith('.' + target + '.') and w[:-1] not in subs:
                    subs.append(w[:-1])
        else:
            # warn 403
            pass
        __log_into_file(thread_tmp_filename, 'a', '\n'.join(subs), language)
        return subs
    except:
        return []


def __netcraft(target, timeout_sec, log_in_file, time_sleep, language, verbose_level, socks_proxy, retries, headers,
               thread_tmp_filename):
    try:
        from core.targets import target_to_host
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
            if n is 3:
                break
            if results.status_code is 200:
                for l in re.compile('<a href="http://toolbar.netcraft.com/site_report\?url=(.*)">').findall(
                        results.content):
                    if '*' not in target_to_host(l) and target_to_host(l).endswith('.' + target) and target_to_host(
                            l) not in subs:
                        subs.append(target_to_host(l))
            else:
                # warn 403
                break
            try:
                url = 'http://searchdns.netcraft.com' + re.compile('<A href="(.*?)"><b>Next page</b></a>').findall(
                    results.content)[0]
            except:
                break
        __log_into_file(thread_tmp_filename, 'a', '\n'.join(subs), language)
        return subs
    except:
        return []


def __threatcrowd(target, timeout_sec, log_in_file, time_sleep, language, verbose_level, socks_proxy, retries, headers,
                  thread_tmp_filename):
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
        n = 0
        url = 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={0}'.format(
            target)
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
                subs = json.loads(results.content)["subdomains"]
            except:
                subs = []
        else:
            # warn 403
            pass
        __log_into_file(thread_tmp_filename, 'a', '\n'.join(subs), language)
        return subs
    except:
        return []


def __dnsdumpster(target, timeout_sec, log_in_file, time_sleep, language, verbose_level, socks_proxy, retries, headers,
                  thread_tmp_filename):
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
        url = 'https://dnsdumpster.com/'
        s = requests.session()
        req = s.get(url)
        csrf_middleware = re.compile("<input type='hidden' name='csrfmiddlewaretoken' value='(.*?)' />",
                                     re.S).findall(req.content)[0]
        req = s.post(url, cookies={'csrftoken': csrf_middleware},
                     data={'csrfmiddlewaretoken': csrf_middleware,
                           'targetip': target},
                     headers={'Referer': url})
        subs = []
        if req.status_code is 200:
            for w in req.content.replace('.<', ' ').replace('<', ' ').replace('>', ' ').rsplit():
                if '*' not in w and w.endswith('.' + target) and w not in subs:
                    subs.append(w)
        else:
            # warn 403
            pass
        __log_into_file(thread_tmp_filename, 'a', '\n'.join(subs), language)
        return subs
    except:
        return []


def __comodo_crt(target, timeout_sec, log_in_file, time_sleep, language, verbose_level, socks_proxy, retries, headers,
                 thread_tmp_filename):
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
                    if '*' not in l and l.endswith('.' + target) and l not in subs:
                        subs.append(l)
            except Exception:
                pass
        else:
            # warn 403
            pass
        __log_into_file(thread_tmp_filename, 'a', '\n'.join(subs), language)
        return subs
    except:
        return []


def __virustotal(target, timeout_sec, log_in_file, time_sleep, language, verbose_level, socks_proxy, retries, headers,
                 thread_tmp_filename):
    try:
        from core.targets import target_to_host
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
        n = 0
        url = 'https://www.virustotal.com/en/domain/{0}/information/'.format(
            target)
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
                    if '*' not in target_to_host(l) and target_to_host(l.strip()).endswith(
                            '.' + target) and target_to_host(l.strip()) not in subs:
                        subs.append(target_to_host(l.strip()))
            except:
                pass
        else:
            # warn 403
            pass
        __log_into_file(thread_tmp_filename, 'a', '\n'.join(subs), language)
        return subs
    except:
        return []


def __ptrarchive(target, timeout_sec, log_in_file, time_sleep, language, verbose_level, socks_proxy, retries, headers,
                 thread_tmp_filename):
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
        n = 0
        url = 'http://ptrarchive.com/tools/search2.htm?label={0}&date=ALL'.format(
            target)
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
                if '*' in sub and sub.endswith('.' + target) and sub not in subs:
                    subs.append(sub)
        else:
            # warn 403
            pass
        __log_into_file(thread_tmp_filename, 'a', '\n'.join(subs), language)
        return subs
    except:
        return []


def __get_subs(target, timeout_sec, log_in_file, time_sleep, language, verbose_level, socks_proxy, retries,
               num, total, extra_requirements=extra_requirements_dict(), headers={
                   'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                   '(KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
                   'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
                   'Accept-Language': 'en-US,en;q=0.9',
                   'Accept-Encoding': 'gzip, deflate, br',
               }):
    total_req = 0
    trying = 0
    threads = []
    thread_tmp_filename = '{}/tmp/thread_tmp_'.format(load_file_path()) + ''.join(
        random.choice(string.ascii_letters + string.digits) for _ in range(20))
    for key in extra_requirements:
        if extra_requirements[key][0] == 'True':
            total_req += 1
    if extra_requirements['subdomain_scan_use_netcraft'][0] == 'True':
        trying += 1
        if verbose_level > 3:
            info(messages(language, "trying_process").format(trying, total_req, num, total, target,
                                                             '(subdomain_scan - netcraft)'))
        t = threading.Thread(target=__netcraft,
                             args=(target, timeout_sec, log_in_file, time_sleep, language, verbose_level,
                                   socks_proxy, retries, headers, thread_tmp_filename))
        threads.append(t)
        t.start()
        threads.append(t)
    if extra_requirements['subdomain_scan_use_ptrarchive'][0] == 'True':
        trying += 1
        if verbose_level > 3:
            info(messages(language, "trying_process").format(
                trying, total_req, num, total, target, 'subdomain_scan - ptrarchive'))
        t = threading.Thread(target=__ptrarchive,
                             args=(target, timeout_sec, log_in_file, time_sleep, language, verbose_level,
                                   socks_proxy, retries, headers, thread_tmp_filename))
        threads.append(t)
        t.start()
        threads.append(t)
    if extra_requirements['subdomain_scan_use_threatcrowd'][0] == 'True':
        trying += 1
        if verbose_level > 3:
            info(
                messages(language, "trying_process").format(trying, total_req, num, total, target, 'subdomain_scan - threatcrowd'))
        t = threading.Thread(target=__threatcrowd,
                             args=(target, timeout_sec, log_in_file, time_sleep, language, verbose_level,
                                   socks_proxy, retries, headers, thread_tmp_filename))
        threads.append(t)
        t.start()
        threads.append(t)
    if extra_requirements['subdomain_scan_use_virustotal'][0] == 'True':
        trying += 1
        if verbose_level > 3:
            info(messages(language, "trying_process").format(
                trying, total_req, num, total, target, 'subdomain_scan - virustotal'))
        t = threading.Thread(target=__virustotal,
                             args=(target, timeout_sec, log_in_file, time_sleep, language, verbose_level,
                                   socks_proxy, retries, headers, thread_tmp_filename))
        threads.append(t)
        t.start()
        threads.append(t)
    if extra_requirements['subdomain_scan_use_comodo_crt'][0] == 'True':
        trying += 1
        if verbose_level > 3:
            info(messages(language, "trying_process").format(
                trying, total_req, num, total, target, 'subdomain_scan - comodo crt'))
        t = threading.Thread(target=__comodo_crt,
                             args=(target, timeout_sec, log_in_file, time_sleep, language, verbose_level,
                                   socks_proxy, retries, headers, thread_tmp_filename))
        threads.append(t)
        t.start()
        threads.append(t)
    if extra_requirements['subdomain_scan_use_dnsdumpster'][0] == 'True':
        trying += 1
        if verbose_level > 3:
            info(messages(language, "trying_process").format(trying, total_req, num,
                                                             total, target, 'subdomain_scan - dnsdumpster'))
        t = threading.Thread(target=__dnsdumpster,
                             args=(target, timeout_sec, log_in_file, time_sleep, language, verbose_level,
                                   socks_proxy, retries, headers, thread_tmp_filename))
        threads.append(t)
        t.start()
        threads.append(t)
    if extra_requirements['subdomain_scan_use_google_dig'][0] == 'True':
        trying += 1
        if verbose_level > 3:
            info(messages(language, "trying_process").format(trying, total_req, num, total, target,
                                                             '(subdomain_scan - google dig)'))
        t = threading.Thread(target=__google_dig,
                             args=(target, timeout_sec, log_in_file, time_sleep, language, verbose_level,
                                   socks_proxy, retries, headers, thread_tmp_filename))
        threads.append(t)
        t.start()
        threads.append(t)
    if extra_requirements['subdomain_scan_use_cert_spotter'][0] == 'True':
        trying += 1
        if verbose_level > 3:
            info(messages(language, "trying_process").format(trying, total_req, num, total, target,
                                                             '(subdomain_scan - cert spotter)'))
        t = threading.Thread(target=__cert_spotter,
                             args=(target, timeout_sec, log_in_file, time_sleep, language, verbose_level,
                                   socks_proxy, retries, headers, thread_tmp_filename))
        threads.append(t)
        t.start()
        threads.append(t)
    # wait for threads
    kill_switch = 0
    try:
        kill_time = -1 if extra_requirements["subdomain_scan_time_limit_seconds"][0] == -1 \
            else int(int(extra_requirements["subdomain_scan_time_limit_seconds"[0]]) / 0.1)
    except:
        kill_time = -1
    while 1:
        time.sleep(0.1)
        kill_switch += 1
        try:
            if threading.activeCount() is 1 or (kill_time is not -1 and kill_switch is kill_time):
                break
        except KeyboardInterrupt:
            break
    try:
        subs = list(set(open(thread_tmp_filename).read().rsplit()))
        os.remove(thread_tmp_filename)
    except:
        subs = []
    return subs


def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id,
          scan_cmd):  # Main function
    from core.targets import target_type
    from core.targets import target_to_host
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
        subs = __get_subs(target, timeout_sec, log_in_file, time_sleep, language, verbose_level, socks_proxy, retries,
                          num, total, extra_requirements=extra_requirements)
        if len(subs) is 0:
            info(messages(language, "no_subdomain_found"))
        if len(subs) is not 0:
            info(messages(language, "len_subdomain_found").format(len(subs)))
            for sub in subs:
                if verbose_level > 2:
                    info(messages(language, "subdomain_found").format(sub))
                data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': '', 'TYPE': 'subdomain_scan',
                                   'DESCRIPTION': sub, 'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id,
                                   'SCAN_CMD': scan_cmd}) + "\n"
                __log_into_file(log_in_file, 'a', data, language)
        if len(subs) is 0 and verbose_level is not 0:
            data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': '', 'TYPE': 'subdomain_scan',
                               'DESCRIPTION': messages(language, "subdomain_found").format(len(subs), ', '.join(subs)
                                                                                           if len(subs) > 0 else 'None'), 'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id,
                               'SCAN_CMD': scan_cmd}) + "\n"
            __log_into_file(log_in_file, 'a', data, language)
        return subs
    else:
        warn(messages(language, "input_target_error").format(
            'subdomain_scan', target))
        return []
