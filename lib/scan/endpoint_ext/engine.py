#!/usr/bin/env python
# -*- coding: utf-8 -*-

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
from gzip import GzipFile
from core.targets import target_to_host
from core.load_modules import load_file_path
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.log import __log_into_file
import requests
import jsbeautifier
from core.compatible import version


if version() == 3:
    from urllib.parse import urlparse
    from io import BytesIO

    readBytesCustom = BytesIO
else:
    from urlparse import urlparse
    from StringIO import StringIO

    readBytesCustom = StringIO


def extra_requirements_dict():
    return {
        "regex": [
            r"""(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^"|']{0,}|)))(?:"|')"""
        ],
    }


user_agent_list = [
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.5) Gecko/20060719 Firefox/1.5.0.5",
    "Googlebot/2.1 ( http://www.googlebot.com/bot.html)",
    "Mozilla/5.0 (X11; U; Linux x86_64; en-US) AppleWebKit/534.13 (KHTML, like Gecko) Ubuntu/10.04"
    " Chromium/9.0.595.0 Chrome/9.0.595.0 Safari/534.13",
    "Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 5.2; WOW64; .NET CLR 2.0.50727)",
    "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51",
    "Mozilla/5.0 (compatible; 008/0.83; http://www.80legs.com/webcrawler.html) Gecko/2008032620",
    "Debian APT-HTTP/1.3 (0.8.10.3)",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Googlebot/2.1 (+http://www.googlebot.com/bot.html)",
    "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
    "YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; "
    "http://help.yahoo.com/help/us/shop/merchant/)",
]
HEADERS = {
    "User-Agent": random.choice(user_agent_list),
    "Accept": "text/html,application/xhtml+xml,application/xml; q=0.9,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


def endpoints_extract(
    target,
    timeout_sec,
    log_in_file,
    time_sleep,
    language,
    verbose_level,
    socks_proxy,
    retries,
    thread_tmp_filename,
    extra_requirements,
    domain,
    scheme,
):
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
                socket.getaddrinfo = getaddrinfo
        r = requests.get(target, verify=False, headers=HEADERS)
        content = jsbeautifier.beautify(r.text)
        regex = re.compile(extra_requirements["regex"][0], re.VERBOSE)
        endpoints = [m.group(1) for m in re.finditer(regex, content)]
        new_endpoints = []
        for endpoint in endpoints:
            if endpoint.startswith("/"):
                endP = scheme + "://" + domain + endpoint
                endpoint = endP
            new_endpoints.append(endpoint)
        __log_into_file(thread_tmp_filename, "a", "\n".join(new_endpoints), language)
        return endpoints
    except:
        return []


def __get_endpoints(
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
    domain,
    scheme,
    extra_requirements=extra_requirements_dict(),
):
    total_req = 0
    trying = 0
    threads = []
    thread_tmp_filename = "{}/tmp/thread_tmp_".format(load_file_path()) + "".join(
        random.choice(string.ascii_letters + string.digits) for _ in range(20)
    )
    for key in extra_requirements:
        if extra_requirements[key][0] == "True":
            total_req += 1
    trying += 1
    if verbose_level > 3:
        info(
            messages(language, "trying_process").format(
                trying, total_req, num, total, target, "(Endpoint Extraction)"
            )
        )
    t = threading.Thread(
        target=endpoints_extract,
        args=(
            target,
            timeout_sec,
            log_in_file,
            time_sleep,
            language,
            verbose_level,
            socks_proxy,
            retries,
            thread_tmp_filename,
            extra_requirements,
            domain,
            scheme,
        ),
    )
    threads.append(t)
    t.start()
    threads.append(t)
    # wait for threads
    kill_switch = 0

    while 1:
        time.sleep(0.1)
        kill_switch += 1
        try:
            if threading.activeCount() == 1:
                break
        except KeyboardInterrupt:
            break
    try:
        endpoints = list(set(open(thread_tmp_filename).read().rsplit()))
        os.remove(thread_tmp_filename)
    except:
        endpoints = []
    return endpoints


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
):
    from core.targets import target_type
    from core.targets import target_to_host
    target_details = urlparse(target)
    scheme = target_details.scheme
    domain = target_details.netloc
    path = target_details.path
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
        if str(scheme + "://" + domain + path)[-3:] == ".js":
            endpoints = __get_endpoints(
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
                domain,
                scheme,
                extra_requirements=extra_requirements,
            )
        else:
            warn(messages(language, "js_input"))
            return False
        if len(endpoints) == 0:
            info(messages(language, "no_endpoints_found"))
        if len(endpoints) != 0:
            info(messages(language, "endpoints_found").format(len(endpoints)))
            for sub in endpoints:
                if verbose_level > 2:
                    info(messages(language, "endpoints_found").format(sub))
                data = (
                    json.dumps(
                        {
                            "HOST": target,
                            "USERNAME": "",
                            "PASSWORD": "",
                            "PORT": "",
                            "TYPE": "endpoint_ext_scan",
                            "DESCRIPTION": sub,
                            "TIME": now(),
                            "CATEGORY": "scan",
                            "SCAN_ID": scan_id,
                            "SCAN_CMD": scan_cmd,
                        }
                    )
                    + "\n"
                )
                __log_into_file(log_in_file, "a", data, language)
        if len(endpoints) == 0 and verbose_level != 0:
            data = (
                json.dumps(
                    {
                        "HOST": target,
                        "USERNAME": "",
                        "PASSWORD": "",
                        "PORT": "",
                        "TYPE": "endpoint_ext_scan",
                        "DESCRIPTION": messages(language, "endpoints_found").format(
                            len(endpoints),
                            ", ".join(endpoints) if len(endpoints) > 0 else "None",
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
        return endpoints
    else:
        warn(
            messages(language, "input_target_error").format("endpoint_ext_scan", target)
        )
        return []
