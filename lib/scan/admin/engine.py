#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import socks
import time
import threading
import string
import json
import requests
import random
import os
from core.alert import warn, messages, info
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.log import __log_into_file
from core._die import __die_failure
from lib.payload.wordlists import useragents
from core.compatible import version
from lib.scan.admin import admin_scan
import six

def extra_requirements_dict():
    return {
        "admin_scan_http_method": ["GET"],
        "admin_scan_random_agent": ["True"],
        "admin_scan_list": admin_scan.admin_scan(),
    }


def check(target, user_agent, timeout_sec, log_in_file, language, time_sleep, thread_tmp_filename, retries,
          http_method, socks_proxy, scan_id, scan_cmd):
    status_codes = [401, 403]
    directory_listing_msgs = ["<title>Index of /", "<a href=\"\\?C=N;O=D\">Name</a>", "Directory Listing for",
                              "Parent Directory</a>", "Last modified</a>", "<TITLE>Folder Listing.",
                              "- Browsing directory "]
    time.sleep(time_sleep)
    try:
        if socks_proxy is not None:
            socks_version = (
                socks.SOCKS5
                if socks_proxy.startswith("socks5://")
                else socks.SOCKS4
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
                socket.getaddrinfo = getaddrinfo
        n = 0
        while 1:
            try:
                if http_method == "GET":
                    r = requests.get(
                        target, timeout=timeout_sec, headers=user_agent
                    )
                elif http_method == "HEAD":
                    r = requests.head(
                        target, timeout=timeout_sec, headers=user_agent
                    )
                content = r.content
                break
            except Exception:
                n += 1
                if n is retries:
                    warn(
                        messages(language, "http_connection_timeout").format(
                            target
                        )
                    )
                    return 1
        if version() == 3:
            content = content.decode("utf8")
        if r.status_code in status_codes:
            log_in_file(thread_tmp_filename, "w", "0", language)
            info(
                messages(language, "found").format(
                    target, r.status_code, r.reason
                ),
                log_in_file,
                "a",
                {
                    "HOST": target_to_host(target),
                    "USERNAME": "",
                    "PASSWORD": "",
                    "PORT": "",
                    "TYPE": "admin_scan",
                    "DESCRIPTION": messages(language, "found").format(
                        target, r.status_code, r.reason
                    ),
                    "TIME": now(),
                    "CATEGORY": "scan",
                    "SCAN_ID": scan_id,
                    "SCAN_CMD": scan_cmd,
                },
                language,
                thread_tmp_filename,
            )
        if r.status_code == 200:
            data = {
                "HOST": target_to_host(target),
                "USERNAME": "",
                "PASSWORD": "",
                "PORT": "",
                "TYPE": "admin_scan",
                "DESCRIPTION": messages(language, "directoy_listing").format(
                    target
                ),
                "TIME": now(),
                "CATEGORY": "scan",
                "SCAN_ID": scan_id,
                "SCAN_CMD": scan_cmd,
            }
            for dlmsg in directory_listing_msgs:
                if dlmsg in content:
                    info(
                        messages(language, "directoy_listing").format(target),
                        log_in_file,
                        "a",
                        data,
                        language,
                        thread_tmp_filename,
                    )
                    __log_into_file(
                        log_in_file,
                        "a\
                        ",
                        json.dumps(data),
                        language,
                    )
                else:
                    info(
                        messages(language, "found").format(
                            target, r.status_code, r.reason
                        ),
                        log_in_file,
                        "a",
                        {
                            "HOST": target_to_host(target),
                            "USERNAME": "",
                            "PASSWORD": "",
                            "PORT": "",
                            "TYPE": "admin_scan",
                            "DESCRIPTION": messages(language, "found").format(
                                target, r.status_code, r.reason
                            ),
                            "TIME": now(),
                            "CATEGORY": "scan",
                            "SCAN_ID": scan_id,
                            "SCAN_CMD": scan_cmd,
                        },
                        language,
                        thread_tmp_filename,
                    )
                break
        return True
    except Exception:
        return False


def test(
    target,
    retries,
    timeout_sec,
    user_agent,
    http_method,
    socks_proxy,
    verbose_level,
    trying,
    total_req,
    total,
    num,
    language,
):
    if verbose_level > 3:
        info(
            messages(language, "trying_message").format(
                trying,
                total_req,
                num,
                total,
                target_to_host(target),
                "default_port",
                "admin_scan",
            )
        )
    if socks_proxy is not None:
        socks_version = (
            socks.SOCKS5
            if socks_proxy.startswith("socks5://")
            else socks.SOCKS4
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
            socket.getaddrinfo = getaddrinfo
    n = 0
    while 1:
        try:
            if http_method == "GET":
                requests.get(target, timeout=timeout_sec, headers=user_agent)
            elif http_method == "HEAD":
                requests.head(target, timeout=timeout_sec, headers=user_agent)

            return 0
        except Exception:
            n += 1
            if n == retries:
                return 1


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
        or target_type(target) != "SINGLE_IPv6"
    ):
        # rand useragent
        user_agent_list = useragents.useragents()
        http_methods = ["GET", "HEAD"]
        user_agent = {"User-agent": random.choice(user_agent_list)}

        # requirements check
        new_extra_requirements = extra_requirements_dict()
        if methods_args is not None:
            for extra_requirement in extra_requirements_dict():
                if extra_requirement in methods_args:
                    new_extra_requirements[extra_requirement] = methods_args[
                        extra_requirement
                    ]
        extra_requirements = new_extra_requirements
        if extra_requirements["admin_scan_http_method"][0] not in http_methods:
            warn(messages(language, "admin_scan_get"))
            extra_requirements["admin_scan_http_method"] = ["GET"]
        random_agent_flag = True
        if extra_requirements["admin_scan_random_agent"][0] == "False":
            random_agent_flag = False
        threads = []
        total_req = len(extra_requirements["admin_scan_list"])
        thread_tmp_filename = "{}/tmp/thread_tmp_".format(
            load_file_path()
        ) + "".join(
            random.choice(string.ascii_letters + string.digits)
            for _ in range(20)
        )
        __log_into_file(thread_tmp_filename, "w", "1", language)
        trying = 0
        if target_type(target) != "HTTP":
            target = 'http://' + target
        if test(str(target), retries, timeout_sec, user_agent, extra_requirements["admin_scan_http_method"][0],
                socks_proxy, verbose_level, trying, total_req, total, num, language) == 0:
            keyboard_interrupt_flag = False
            for idir in extra_requirements["admin_scan_list"]:
                # time.sleep(0.001)
                if random_agent_flag:
                    user_agent = {'User-agent': random.choice(user_agent_list)}
                if target.endswith("/"):
                    target = target[:-1]
                if idir.startswith("/"):
                    idir = idir[1:]
                t = threading.Thread(target=check,
                                     args=(
                                         target + "/" + idir, user_agent, timeout_sec, log_in_file, language,
                                         time_sleep, thread_tmp_filename, retries,
                                         extra_requirements[
                                             "admin_scan_http_method"][0],
                                         socks_proxy, scan_id, scan_cmd))
                threads.append(t)
                t.start()
                trying += 1
                if verbose_level > 3:
                    info(
                        messages(language, "trying_message").format(
                            trying,
                            total_req,
                            num,
                            total,
                            target_to_host(target),
                            "default_port",
                            "admin_scan",
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

        else:
            warn(messages(language, "open_error").format(target))

        # wait for threads
        kill_switch = 0
        kill_time = (
            int(timeout_sec / 0.1) if int(timeout_sec / 0.1) != 0 else 1
        )

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
            if verbose_level != 0:
                data = {'HOST': target_to_host(target), 'USERNAME': '', 'PASSWORD': '', 'PORT': '', 'TYPE': 'admin_scan',
                     'DESCRIPTION': messages(language, "directory_file_404").format(target, "default_port"), 'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id,
                     'SCAN_CMD': scan_cmd}
                info(messages(language, "directory_file_404").format(
                    target, "default_port"), log_in_file, "a",
                    data, language, thread_tmp_filename)
                __log_into_file(log_in_file, 'a', json.dumps(data), language)
        os.remove(thread_tmp_filename)
    else:
        warn(
            messages(language, "input_target_error").format(
                "admin_scan", target
            )
        )
