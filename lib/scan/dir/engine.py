#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import socks
import time
import json
import threading
import string
import requests
import random
import os
from core.alert import warn, info, messages
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.log import __log_into_file
from core.compatible import version
from lib.scan.dir import wordlist
from lib.payload.wordlists import useragents
import six
from difflib import SequenceMatcher


SESSION = requests.Session()


def extra_requirements_dict():
    return {
        "dir_scan_http_method": ["GET"],
        "dir_scan_random_agent": ["True"],
        "dir_scan_list": wordlist.wordlists()
    }


def check(target, user_agent, timeout_sec, log_in_file, language, time_sleep, thread_tmp_filename, retries,
          http_method, length, socks_proxy, scan_id, scan_cmd):
    status_codes = [401, 403]
    directory_listing_msgs = ["<title>Index of /", "<a href=\"\\?C=N;O=D\">Name</a>", "Directory Listing for",
                              "Parent Directory</a>", "Last modified</a>", "<TITLE>Folder Listing.",
                              "- Browsing directory "]
    time.sleep(time_sleep)
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
        
        while 1:
            try:
                if http_method == "GET":
                    r = SESSION.get(
                        target, verify=False, timeout=timeout_sec, headers=user_agent)
                    content = r.text
                elif http_method == "HEAD":
                    r = SESSION.head(
                        target, verify=False, timeout=timeout_sec, headers=user_agent)
                break
            except Exception:
                n += 1
                if n == retries:
                    # warn(messages(language, "http_connection_timeout").format(target))
                    return 1
        diff = SequenceMatcher(None, str(length), str(len(content)))
        if r.status_code in status_codes:
            if(diff.ratio()<0.95):
                info(messages(language, "found").format(
                    target, r.status_code, r.reason))
                __log_into_file(thread_tmp_filename, 'w', '0', language)
                data = json.dumps({'HOST': target_to_host(target), 'USERNAME': '', 'PASSWORD': '',
                                'PORT': "", 'TYPE': 'dir_scan',
                                'DESCRIPTION': messages(language, "found").format(target, r.status_code, r.reason),
                                'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
                __log_into_file(log_in_file, 'a', data, language)

        if r.status_code == 200:
            if(diff.ratio()<0.95):
                for dlmsg in directory_listing_msgs:
                    if dlmsg in content:
                        info(messages(language, "directoy_listing").format(target))
        
                        data = json.dumps({'HOST': target_to_host(target), 'USERNAME': '', 'PASSWORD': '',
                                            'PORT': "", 'TYPE': 'dir_scan',
                                            'DESCRIPTION': messages(language, "directoy_listing").format(target), 'TIME': now(),
                                            'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
                        __log_into_file(log_in_file, 'a', data, language)
                    else:
                        info(messages(language, "found").format(
                            target, r.status_code, r.reason))
        
                        data = json.dumps({'HOST': target_to_host(target), 'USERNAME': '', 'PASSWORD': '',
                                        'PORT': "", 'TYPE': 'dir_scan',
                                        'DESCRIPTION': messages(language, "found").format(target, r.status_code, r.reason),
                                        'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
                        __log_into_file(log_in_file, 'a', data, language)
                    break
        return True
    except Exception:
        return False


def test(target, retries, timeout_sec, user_agent, http_method, socks_proxy, verbose_level, trying, total_req, total,
         num, language):
    if verbose_level > 3:
        info(messages(language, "trying_message").format(trying, total_req, num, total, target_to_host(target), "default_port",
                                                         'dir_scan'))
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
    while 1:
        try:
            if http_method == "GET":
                SESSION.get(target, verify=False, timeout=timeout_sec,
                                 headers=user_agent)
            elif http_method == "HEAD":
                SESSION.head(target, verify=False, timeout=timeout_sec,
                                  headers=user_agent)
            return 0
        except:
            n += 1
            if n == retries:
                return 1


def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(
            target) != 'HTTP' or target_type(target) != 'SINGLE_IPv6':
        # rand useragent
        user_agent_list = useragents.useragents()
        http_methods = ["GET", "HEAD"]
        user_agent = {'User-agent': random.choice(user_agent_list)}

        # requirements check
        new_extra_requirements = extra_requirements_dict()
        if methods_args is not None:
            for extra_requirement in extra_requirements_dict():
                if extra_requirement in methods_args:
                    new_extra_requirements[
                        extra_requirement] = methods_args[extra_requirement]
        extra_requirements = new_extra_requirements
        if extra_requirements["dir_scan_http_method"][0] not in http_methods:
            warn(messages(language, "dir_scan_get"))
            extra_requirements["dir_scan_http_method"] = ["GET"]
        random_agent_flag = True
        if extra_requirements["dir_scan_random_agent"][0] == "False":
            random_agent_flag = False
        threads = []
        total_req = len(extra_requirements["dir_scan_list"])
        thread_tmp_filename = '{}/tmp/thread_tmp_'.format(load_file_path()) + ''.join(
            random.choice(string.ascii_letters + string.digits) for _ in range(20))
        __log_into_file(thread_tmp_filename, 'w', '1', language)
        trying = 0
        if target_type(target) != "HTTP":
            target = 'http://' + target
        nowh3r3 = target + "/ThisFileIs404"
        try:
            r = SESSION.get(nowh3r3, verify=False, headers=user_agent, timeout=timeout_sec)
            length = len(r.text)
        except Exception:
            length = 0
        if test(str(target), retries, timeout_sec, user_agent, extra_requirements["dir_scan_http_method"][0],
                socks_proxy, verbose_level, trying, total_req, total, num, language) == 0:
            keyboard_interrupt_flag = False
            for idir in extra_requirements["dir_scan_list"]:
                if random_agent_flag:
                    user_agent = {'User-agent': random.choice(user_agent_list)}
                if target.endswith("/"):
                    target = target[:-1]
                if idir.startswith("/"):
                    idir = idir[1:]
                t = threading.Thread(target=check,
                                     args=(
                                         target + '/' + idir, user_agent, timeout_sec, log_in_file, language,
                                         time_sleep, thread_tmp_filename, retries,
                                         extra_requirements[
                                             "dir_scan_http_method"][0], length,
                                         socks_proxy, scan_id, scan_cmd))
                threads.append(t)
                t.start()
                trying += 1
                if verbose_level > 3:
                    info(messages(language, "trying_message").format(trying, total_req, num, total, target_to_host(target),
                                                                     "default_port", 'dir_scan'))
                while 1:
                    try:
                        if threading.activeCount() >= thread_number:
                            time.sleep(0.01)
                        else:
                            break
                    except KeyboardInterrupt:
                        keyboard_interrupt_flag = True
                        break
                if keyboard_interrupt_flag:
                    break

        else:
            warn(messages(language, "open_error").format(target))

        # wait for threads
        kill_switch = 0
        kill_time = int(
            timeout_sec / 0.1) if int(timeout_sec / 0.1) != 0 else 1
        while 1:
            time.sleep(0.1)
            kill_switch += 1
            try:
                if threading.activeCount() == 1 or kill_switch == kill_time:
                    break
            except KeyboardInterrupt:
                break
        thread_write = int(open(thread_tmp_filename).read().rsplit()[0])
        if thread_write == 1:
            info(messages(language, "directory_file_404").format(
                target, "default_port"))
            if verbose_level != 0:
                data = json.dumps(
                    {'HOST': target_to_host(target), 'USERNAME': '', 'PASSWORD': '', 'PORT': '', 'TYPE': 'dir_scan',
                     'DESCRIPTION': messages(language, "no_open_ports"), 'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id,
                     'SCAN_CMD': scan_cmd})
                __log_into_file(log_in_file, 'a', data, language)
        os.remove(thread_tmp_filename)
    else:
        warn(messages(language, "input_target_error").format('dir_scan', target))
