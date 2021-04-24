#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import socks
import time
import json
import re
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
from lib.payload.wordlists import useragents
from bs4 import BeautifulSoup


def extra_requirements_dict():
    return {
        "email_scan_http_method": ["GET", ],
        "email_scan_random_agent": ["True", ],
        "email_scan_file_ext": ["jpeg", "exif", "tiff", "gif", "bmp", "png",
                                "ppm", "pgm", "pbm", "pnm", "webp", "hdr",
                                "heif", "bat", "bpg", "cgm", "svg"]
    }


def __get_emails(target, user_agent, timeout_sec, log_in_file, language, time_sleep,
                 thread_tmp_filename, retries, socks_proxy, scan_id, scan_cmd,
                 extra_requirements=extra_requirements_dict()
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
        n = 0
        while 1:
            try:
                if extra_requirements["email_scan_http_method"][0] == "GET":
                    r = requests.get(
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
        if r.status_code == 200:
            emails = re.findall(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}', content)
            for email in emails:
                if email[-3:] not in extra_requirements["email_scan_file_ext"]:
                    __log_into_file(
                        thread_tmp_filename,
                        "a",
                        email,
                        language
                    )
        return True
    except Exception:
        return False


def __get_targets(
        target,
        timeout_sec,
        user_agent,
        time_sleep,
        language,
        verbose_level,
        socks_proxy,
        retries,
        num,
        total,
        extra_requirements=extra_requirements_dict()):

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
    targets = [target, ]
    while 1:
        try:
            if extra_requirements["email_scan_http_method"][0] == "GET":
                req = requests.get(target, timeout=timeout_sec, headers=user_agent)
                soup = BeautifulSoup(req.text, "html.parser")
                tags = soup.find_all('a')
                for tag in tags:
                    link = tag.get('href', None)
                    if link is not None:
                        if link[0:4] == 'http':
                            targets.append(link)
                        elif link[0] == '/':
                            link = target + link
                            targets.append(link)
            return targets
        except Exception as e:
            n += 1
            if n == retries:
                targets = []
                return targets


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
        http_methods = ["GET", ]
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
        if extra_requirements["email_scan_http_method"][0] not in http_methods:
            warn(messages(language, "email_scan_get"))
            extra_requirements["email_scan_http_method"] = ["GET"]
        random_agent_flag = True
        if extra_requirements["email_scan_random_agent"][0] == "False":
            random_agent_flag = False

        thread_tmp_filename = "{}/tmp/thread_tmp_".format(
            load_file_path()
        ) + "".join(
            random.choice(string.ascii_letters + string.digits)
            for _ in range(20)
        )
        trying = 0
        if target_type(target) != "HTTP":
            target = 'http://' + target

        targets = __get_targets(target, timeout_sec, user_agent, time_sleep, language, verbose_level, socks_proxy,
                                retries, num, total, extra_requirements=extra_requirements)

        threads = []
        total_req = len(targets)
        keyboard_interrupt_flag = False
        if len(targets) != 0:
            for target in targets:
                if random_agent_flag:
                    user_agent = {'User-agent': random.choice(user_agent_list)}
                if target.endswith("/"):
                    target = target[:-1]
                t = threading.Thread(
                    target=__get_emails,
                    args=(target, user_agent, timeout_sec, log_in_file, language, time_sleep,
                          thread_tmp_filename, retries, socks_proxy, scan_id, scan_cmd,
                          extra_requirements,
                          ))
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
                            "email_scan",
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
        try:
            emails_list = list(set(open(thread_tmp_filename).read().rsplit()))
            os.remove(thread_tmp_filename)
        except Exception:
            emails_list = []

        if len(emails_list) == 0 and verbose_level != 0:
            info(messages(language, "no_emails_found"))
            data = {'HOST': target_to_host(target), 'USERNAME': '', 'PASSWORD': '', 'PORT': '',
                    'TYPE': 'email_scan',
                    'DESCRIPTION': messages(language, "email_404").format(target, "default_port"),
                    'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id,
                    'SCAN_CMD': scan_cmd}
            info(messages(language, "email_404").format(
                target, "default_port"), log_in_file, "a",
                data, language, thread_tmp_filename)
            __log_into_file(log_in_file, 'a', json.dumps(data), language)
        else:
            info(messages(language, "len_email_found").format(len(emails_list)))
            for email in emails_list:
                if verbose_level > 2:
                    info(messages(language, "email_found").format(email))
                data = json.dumps({
                    "HOST": target_to_host(target),
                    "USERNAME": "",
                    "PASSWORD": "",
                    "PORT": "",
                    "TYPE": "email_scan",
                    "DESCRIPTION": email,
                    "TIME": now(),
                    "CATEGORY": "scan",
                    "SCAN_ID": scan_id,
                    "SCAN_CMD": scan_cmd,
                })
                __log_into_file(log_in_file, 'a', data, language)
    else:
        warn(
            messages(language, "input_target_error").format(
                "email_scan", target
            )
        )
