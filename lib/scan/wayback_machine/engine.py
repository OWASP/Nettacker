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
import re
import os
from core.alert import info, messages, warn
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.log import __log_into_file
import requests


INCORRECT_URL = 0


def extra_requirements_dict():
    return {"extensions": [""]}


def __wayback_machine_scan(
    target,
    timeout_sec,
    log_in_file,
    time_sleep,
    language,
    verbose_level,
    socks_proxy,
    retries,
    headers,
    thread_tmp_filename,
    extra_requirement,
):
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

        try:
            requests.get(target)
        except Exception:
            global INCORRECT_URL
            INCORRECT_URL = 1
            warn(messages(language, "open_error").format(target))
            return []

        if target_type(target) == "HTTP":
            target = target_to_host(target)

        request_url = """http://web.archive.org/cdx/search/cdx?url=*.{0}/*
        &output=json&fl=original&collapse=urlkey&page=/""".format(
            target
        )
        try:
            req = requests.get(request_url)
            temp = []
            t = json.loads(req.text)
            for i in t:
                temp.extend(i)
        except Exception:
            warn(
                messages(language, "input_target_error").format(
                    "wayback_error", target
                )
            )
            return []
        paths = []
        count = 0
        for i in range(1, len(temp)):
            if extra_requirement["extensions"][0] != "":
                not_contains = re.compile(
                    "|".join(extra_requirement["extensions"])
                )
                if temp[i] not in paths and not_contains.search(
                    temp[i].encode("ascii", "ignore")
                ):
                    paths.append(temp[i])
                    count += 1
            else:
                paths.append(temp[i])
        __log_into_file(thread_tmp_filename, "a", "\n".join(paths), language)
        with open(thread_tmp_filename, "r") as f:
            lines = f.readlines()
        with open(thread_tmp_filename, "w") as f:
            for line in lines:
                if line.strip("\n") != "1":
                    f.write(line)
        return paths
    except Exception:
        return []


def __wayback_machine(
    target,
    timeout_sec,
    log_in_file,
    time_sleep,
    language,
    verbose_level,
    socks_proxy,
    retries,
    num,
    total,
    extra_requirements=extra_requirements_dict(),
    headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)\
            AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,\
            image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
    },
):
    total_req = 0
    trying = 0
    threads = []
    thread_tmp_filename = "{}/tmp/thread_tmp_".format(
        load_file_path()
    ) + "".join(
        random.choice(string.ascii_letters + string.digits) for _ in range(20)
    )
    for key in extra_requirements:
        if extra_requirements[key][0] == "True":
            total_req += 1
    trying += 1
    if verbose_level > 3:
        info(
            messages(language, "trying_message").format(
                trying, total_req, num, total, target, "Web.archive.org",
            )
        )
    t = threading.Thread(
        target=__wayback_machine_scan,
        args=(
            target,
            timeout_sec,
            log_in_file,
            time_sleep,
            language,
            verbose_level,
            socks_proxy,
            retries,
            headers,
            thread_tmp_filename,
            extra_requirements,
        ),
    )
    threads.append(t)
    t.start()
    threads.append(t)
    # wait for threads
    kill_switch = 0
    paths = []
    while 1:
        time.sleep(0.2)
        kill_switch += 0.3
        kill_time = (
            int(timeout_sec / 0.1) if int(timeout_sec / 0.1) != 0 else 1
        )
        try:
            if threading.activeCount() == 1 or kill_switch == kill_time:
                break
        except KeyboardInterrupt:
            break
    try:
        paths = list(set(open(thread_tmp_filename).read().rsplit()))
        os.remove(thread_tmp_filename)
    except Exception:
        paths = []
    return paths


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
        # requirements check
        new_extra_requirements = extra_requirements_dict()
        if methods_args is not None:
            for extra_requirement in extra_requirements_dict():
                if extra_requirement in methods_args:
                    new_extra_requirements[extra_requirement] = methods_args[
                        extra_requirement
                    ]
        extra_requirements = new_extra_requirements
        paths = __wayback_machine(
            target,
            timeout_sec,
            log_in_file,
            time_sleep,
            language,
            verbose_level,
            socks_proxy,
            retries,
            num,
            total,
            extra_requirements=extra_requirements,
        )

        if len(paths) == 0 and INCORRECT_URL != 1:
            info(
                messages(language, "no_path_found")
            )
        if len(paths) != 0:
            info(messages(language, "wayback_machine_scan").format(len(paths)))
            for path in paths:
                if verbose_level > 2:
                    info(messages(language, "path_found").format(path))
                try:
                    data = (
                        json.dumps(
                            {
                                "HOST": target,
                                "USERNAME": "",
                                "PASSWORD": "",
                                "PORT": "",
                                "TYPE": "wayback_machine_scan",
                                "DESCRIPTION": path,
                                "TIME": now(),
                                "CATEGORY": "scan",
                                "SCAN_ID": scan_id,
                                "SCAN_CMD": scan_cmd,
                            }
                        )
                        + "\n"
                    )
                    __log_into_file(log_in_file, "a", data, language)
                except Exception:
                    continue
        if len(paths) == 0 and verbose_level != 0:
            data = (
                json.dumps(
                    {
                        "HOST": "sdf",
                        "USERNAME": "",
                        "PASSWORD": "",
                        "PORT": "",
                        "TYPE": "wayback_machine_scan",
                        "DESCRIPTION": messages(language, "path_found").format(
                            path
                        ),
                        "TIME": now(),
                        "CATEGORY": "scan",
                        "SCAN_ID": scan_id,
                        "SCAN_CMD": scan_cmd,
                    }
                )
                + "\n"
            )
            __log_into_file(log_in_file, "a", data, language)
        return paths
    else:
        warn(
            messages(language, "input_target_error").format(
                "wayback_machine_scan", target
            )
        )
        return []
