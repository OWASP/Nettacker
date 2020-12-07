#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Aman Gupta , github.com/aman566

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
import logging
import ssl
from core.alert import *
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.log import __log_into_file
import requests
from six import text_type


def extra_requirements_dict():
    return {
        "whatcms_ports": [443],
        "whatcms_api_key": ["test_api_key"],
    }

CHECK = 0
SESSION = requests.Session()
CMS_CODES = [0, 102, 123, 201, 202, 203, 204]

def conn(targ, port, timeout_sec, socks_proxy):
    try:
        if socks_proxy is not None:
            socks_version = (
                socks.SOCKS5 if socks_proxy.startswith("socks5://") else socks.SOCKS4
            )
            socks_proxy = socks_proxy.rsplit("://")[1]
            if "@" in socks_proxy:
                socks_username = socks_proxy.rsplit(":")[0]
                socks_password = socks_proxy.rsplit(":")[1].rsplit("@")[0]
                socks.set_default_proxy(
                    socks_version,
                    str(socks_proxy.rsplit("@")[1].rsplit(":")[0]),
                    int(socks_proxy.rsplit(":")[-1]),
                    username=socks_username,
                    password=socks_password,
                )
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo
            else:
                socks.set_default_proxy(
                    socks_version,
                    str(socks_proxy.rsplit(":")[0]),
                    int(socks_proxy.rsplit(":")[1]),
                )
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sys.stdout.flush()
        s.settimeout(timeout_sec)
        s.connect((targ, port))
        return s
    except Exception:
        return None


def whatcms(
    target,
    port,
    timeout_sec,
    log_in_file,
    language,
    time_sleep,
    thread_tmp_filename,
    socks_proxy,
    scan_id,
    scan_cmd,
    whatcms_api_key,
):
    try:
        try:
            s = conn(target, port, timeout_sec, socks_proxy)
        except Exception:
            return False
        if not s:
            return False
        else:
            global cms_name
            headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:77.0) Gecko/20100101 Firefox/77.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.7,ru;q=0.3",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "Keep-Alive",
                "Upgrade-Insecure-Requests": "1",
                "X-Requested-With": "XMLHttpRequest",
            }
            check_api_key_is_valid = (
                "https://whatcms.org/API/Status?key=" + whatcms_api_key
            )
            global CHECK
            if CHECK == 0:
                check = SESSION.get(
                    check_api_key_is_valid, headers=headers, verify=False, timeout=timeout_sec
                )
                api_result_code = json.loads(check.text)["result"]["code"]
                if api_result_code == 101:
                    warn(
                        messages(language, "Invalid_whatcms_api_key").format(
                            "Invalid API Key"
                        )
                    )
                    return
                CHECK = 1
            info(messages(language, "searching_whatcms_database").format(target))
            requests_url = (
                "https://whatcms.org/API/CMS?key=" + whatcms_api_key + "&url=" + target
            )
            while 1:
                try:
                    req = SESSION.get(requests_url, verify=False, headers=headers, timeout=timeout_sec)
                    cms_name = json.loads(req.text)["result"]["name"]
                    cms_version = json.loads(req.text)["result"]["version"]
                    status_codes = json.loads(req.text)["result"]["code"]
                    if status_codes == 200:
                        if cms_version:
                            cms_name += " version " + cms_version
                        return cms_name
                    elif status_codes == 121:
                        warn(messages(language, "whatcms_monthly_quota_exceeded"))
                        return
                    elif status_codes in CMS_CODES:
                        return
                except requests.exceptions.Timeout:
                    time.sleep(5)
    except Exception:
        return False


def __whatcms(
    target,
    port,
    timeout_sec,
    log_in_file,
    language,
    time_sleep,
    thread_tmp_filename,
    socks_proxy,
    scan_id,
    scan_cmd,
    whatcms_api_key,
):
    if whatcms(
        target,
        port,
        timeout_sec,
        log_in_file,
        language,
        time_sleep,
        thread_tmp_filename,
        socks_proxy,
        scan_id,
        scan_cmd,
        whatcms_api_key,
    ):
        info(messages(language, "found").format(target, "CMS Name", cms_name))
        __log_into_file(thread_tmp_filename, "w", "0", language)
        data = json.dumps(
            {
                "HOST": target,
                "USERNAME": "",
                "PASSWORD": "",
                "PORT": port,
                "TYPE": "whatcms_scan",
                "DESCRIPTION": messages(language, "found").format(
                    target, "CMS Name", cms_name
                ),
                "TIME": now(),
                "CATEGORY": "scan",
                "SCAN_ID": scan_id,
                "SCAN_CMD": scan_cmd,
            }
        )
        __log_into_file(log_in_file, "a", data, language)
        return True
    else:
        return False


def start(
    target,
    users,
    passwds,
    ports,
    timeout_sec,
    thread_number,
    num,
    total,
    log_in_file,
    time_sleep,
    language,
    verbose_level,
    socks_proxy,
    retries,
    methods_args,
    scan_id,
    scan_cmd,
):  # Main function
    if (
        target_type(target) != "SINGLE_IPv4"
        or target_type(target) != "DOMAIN"
        or target_type(target) != "HTTP"
    ):
        # requirements check
        new_extra_requirements = extra_requirements_dict()
        if methods_args is not None:
            for extra_requirement in extra_requirements_dict():
                if extra_requirement in methods_args:
                    new_extra_requirements[extra_requirement] = methods_args[
                        extra_requirement
                    ]
        extra_requirements = new_extra_requirements
        if ports is None:
            ports = extra_requirements["whatcms_ports"]
        if target_type(target) == "HTTP":
            target = target_to_host(target)
        threads = []
        total_req = len(ports)
        thread_tmp_filename = "{}/tmp/thread_tmp_".format(load_file_path()) + "".join(
            random.choice(string.ascii_letters + string.digits) for _ in range(20)
        )
        __log_into_file(thread_tmp_filename, "w", "1", language)
        trying = 0
        keyboard_interrupt_flag = False
        for port in ports:
            port = int(port)
            t = threading.Thread(
                target=__whatcms,
                args=(
                    target,
                    int(port),
                    timeout_sec,
                    log_in_file,
                    language,
                    time_sleep,
                    thread_tmp_filename,
                    socks_proxy,
                    scan_id,
                    scan_cmd,
                    extra_requirements["whatcms_api_key"][0],
                ),
            )
            threads.append(t)
            t.start()
            trying += 1
            if verbose_level > 3:
                info(
                    messages(language, "trying_message").format(
                        trying, total_req, num, total, target, port, "whatcms_scan",
                    )
                )
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
        # wait for threads
        kill_switch = 0
        kill_time = int(timeout_sec / 0.1) if int(timeout_sec / 0.1) != 0 else 1
        while 1:
            time.sleep(0.1)
            kill_switch += 1
            try:
                if threading.activeCount() == 1:
                    break
            except KeyboardInterrupt:
                break
        thread_write = int(open(thread_tmp_filename).read().rsplit()[0])
        if thread_write == 1 and verbose_level != 0:
            info(messages(language, "not_found"))
            data = json.dumps(
                {
                    "HOST": target,
                    "USERNAME": "",
                    "PASSWORD": "",
                    "PORT": "",
                    "TYPE": "whatcms_scan",
                    "DESCRIPTION": messages(language, "not_found"),
                    "TIME": now(),
                    "CATEGORY": "scan",
                    "SCAN_ID": scan_id,
                    "SCAN_CMD": scan_cmd,
                }
            )
            __log_into_file(log_in_file, "a", data, language)
        os.remove(thread_tmp_filename)

    else:
        warn(messages(language, "input_target_error").format("whatcms_scan", target))
