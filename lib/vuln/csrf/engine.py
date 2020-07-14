#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Aman Gupta , github.com/aman566

# Possible attacks in CSRF:
# CSRF with no defenses(No token present)
# No validations when the token is deleted entirely
# Referer Header validations in CSRF


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
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.log import __log_into_file
import logging
import requests
from bs4 import BeautifulSoup
from core.compatible import version

if version() == 3:
    from urllib.parse import urlparse
else:
    from urlparse import urlparse


def extra_requirements_dict():
    return {
        "csrf_vuln_ports": [80, 443],
        "cookies": ["fake"],
    }


definitions = set()
csrf_vulnerable = ""

COMMON_CSRF_NAMES = (
    "csrf_token",
    "CSRFName",
    "CSRFToken",
    "anticsrf",
    "__RequestVerificationToken",
    "token",
    "csrf",
    "YII_CSRF_TOKEN",
    "yii_anticsrf" "[_token]",
    "_csrf_token",
    "csrfmiddlewaretoken",
)

COUNT = set()

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml; q=0.9,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
}


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
    except:
        return None


def csrf_vuln(
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
    extra_requirements,
):
    try:
        s = conn(target_to_host(target), port, timeout_sec, socks_proxy)
        if not s:
            return False
        else:
            target_details = urlparse(target)
            scheme = target_details.scheme
            domain = target_details.netloc
            path = target_details.path
            if target_type(target) != "HTTP" and port == 443:
                target = "https://" + domain + path
            if target_type(target) != "HTTP" and port == 80:
                target = "http://" + domain + path
            if extra_requirements["cookies"][0] != "fake":
                HEADERS["Cookie"] = extra_requirements["cookies"].encode("utf-8")

            try:
                # Trying to see if Authorization: Bearer is needed in http requests. If needed that no CSRF attack is possible in 99% cases.
                HEADERS["Access-Control-Request-Headers"] = "Authorization"
                options_enabled = requests.options(
                    target, verify=False, headers=HEADERS, timeout=10
                )
                if (
                    "authorization"
                    in options_enabled.headers["Access-Control-Allow-Headers"].lower()
                ):
                    return
            except Exception:
                pass
            global csrf_vulnerable
            try:
                # If in set-cookie response header SameSite=Lax|strict is present then CSRF is not possible.
                set_cookie_session = requests.Session()
                is_present = set_cookie_session.get(
                    target, headers=HEADERS, verify=False, timeout=10
                )
                for set_cookie in is_present.headers:
                    if set_cookie.lower() == "set-cookie":
                        if "samesite=none" in is_present.headers[set_cookie].lower():
                            definitions.add(
                                "CSRF due to missing Lax|Strict value in SameSite attribute"
                            )
                            COUNT.add(True)
            except Exception:
                pass
            res = requests.get(target, verify=False, headers=HEADERS, timeout=10)
            soup = BeautifulSoup(res.text, "html.parser")
            forms = soup.find_all("form")
            if forms:
                hidden = requests.get(target, headers=HEADERS, verify=False, timeout=10)
                # In 95% cases if type="hidden" is not present in the forms are present that most probably that is CSRF token value. In that case CSRF is possible.
                if 'type="hidden"' not in hidden.text.lower():
                    definitions.add("\nCSRF with no defenses(tokens)")
                    COUNT.add(True)
                for form in forms:
                    # finding forms in order to find CSRF vulnerabilities
                    try:
                        details = {}
                        action = form.attrs.get("action").lower()
                        method = form.attrs.get("method", "get").lower()
                        inputs = []
                        for input_tag in form.find_all("input"):
                            input_type = input_tag.attrs.get("type", "text")
                            input_name = input_tag.attrs.get("name")
                            input_value = input_tag.attrs.get("value", "")
                            inputs.append(
                                {
                                    "type": input_type,
                                    "name": input_name,
                                    "value": input_value,
                                }
                            )
                        details["action"] = action
                        details["method"] = method
                        details["inputs"] = inputs
                        form_details = details
                        # print(details)
                        data = {}
                        for input_tag in form_details["inputs"]:
                            if input_tag["type"] == "hidden":
                                temperory = 0
                                for name in COMMON_CSRF_NAMES:
                                    if input_tag["name"] == name and temperory == 0:
                                        data[input_tag["name"]] = input_tag["value"]
                                        token_name = name
                                        temperory = 1
                                        break
                                if temperory == 0:
                                    data[input_tag["name"]] = input_tag["value"]
                            elif input_tag["type"] != "submit":
                                in_type = input_tag["type"]
                                if in_type == "checkbox":
                                    data[input_tag["name"]] = True
                                elif in_type == "email":
                                    data[input_tag["name"]] = "test@test.com"
                                elif in_type == "password":
                                    data[input_tag["name"]] = "testing@123"
                                elif in_type == "hidden":
                                    data[input_tag["name"]] = input_tag["value"]
                        temp = HEADERS
                        if form_details["action"].startswith("http"):
                            final_target = form_details["action"]
                        elif not form_details["action"].startswith("/"):
                            if not path.endswith("/"):
                                path += "/"
                            final_target = (
                                scheme + "://" + domain + path + form_details["action"]
                            )
                        else:
                            final_target = scheme + "://" + domain + form_details["action"]
                        try:
                            for key in data.keys():
                                # In general some websites do not accept if token is manipulated but accepts when the token is stripped. So if token is there and after deleting the value, if request is successful then CSRF is possible.
                                if key == token_name:
                                    del data[key]
                                    try:
                                        if form_details["method"] == "post":
                                            token_abs = requests.post(
                                                final_target,
                                                headers=temp,
                                                data=data,
                                                timeout=10,
                                                verify=False,
                                            )
                                        elif form_details["method"] == "get":
                                            token_abs = requests.get(
                                                final_target,
                                                headers=temp,
                                                params=data,
                                                timeout=10,
                                                verify=False,
                                            )
                                    except Exception:
                                        logging.exception("message")
                                    if token_abs.status_code in [
                                        301,
                                        302,
                                        307,
                                        200,
                                        201,
                                        204,
                                    ]:
                                        definitions.add(
                                            "\nCSRF where token validation depends on token being present"
                                        )
                                        COUNT.add(True)
                        except Exception:
                            pass
                        # Some web application do verify the CSRF using Referer headers. Meaning if referer header contains their own domain value than the request is successful but if referer header is manipulated than the access is denied. In some cases deleting the referer headers make the CSRF possible.
                        temp["Referer"] = "https://evil.com"
                        try:
                            if form_details["method"] == "post":
                                res = requests.post(
                                    final_target,
                                    headers=temp,
                                    data=data,
                                    verify=False,
                                    timeout=10,
                                )
                            elif form_details["method"] == "get":
                                res = requests.get(
                                    final_target,
                                    headers=temp,
                                    data=data,
                                    verify=False,
                                    timeout=10,
                                )
                        except requests.exceptions.ConnectTimeout:
                            # logging.exception("message")
                            pass
                        if res.status_code in [400, 401, 403, 500, 503, 404]:
                            try:
                                temp.pop("Referer")
                            except:
                                pass
                            # res = requests.get(final_target, verify=False, timeout=timeout_sec, headers=temp)
                            try:
                                if form_details["method"] == "post":
                                    res = requests.post(
                                        final_target,
                                        headers=temp,
                                        data=data,
                                        timeout=10,
                                        verify=False,
                                    )
                                elif form_details["method"] == "get":
                                    res = requests.get(
                                        final_target,
                                        headers=temp,
                                        data=data,
                                        timeout=10,
                                        verify=False,
                                    )
                            except Exception:
                                logging.exception("message")
                                pass
                            if str(res.status_code).startswith("2") or str(
                                res.status_code
                            ).startswith("3"):
                                definitions.add(
                                    "\nCSRF Stripping Referer header makes the request successfull"
                                )
                                COUNT.add(True)
                    except Exception:
                        pass
                if True in COUNT:
                    csrf_vulnerable = "\n".join(definitions)
                    return csrf_vulnerable
                else:
                    return False
            else:
                return False
    except:
        # logging.exception("message")
        return False


def __csrf(
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
    extra_requirements,
):
    if csrf_vuln(
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
        extra_requirements,
    ):
        info(
            messages(language, "target_vulnerable").format(
                target, port, "Cross-Site Request Forgery"
            )
        )
        __log_into_file(thread_tmp_filename, "w", "0", language)
        data = json.dumps(
            {
                "HOST": target,
                "USERNAME": "",
                "PASSWORD": "",
                "PORT": port,
                "TYPE": "csrf_vuln",
                "DESCRIPTION": messages(language, "vulnerable").format(csrf_vulnerable),
                "TIME": now(),
                "CATEGORY": "vuln",
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
            val = str(list(methods_args.keys())[0]).split("=", 1)[1]
            for extra_requirement in extra_requirements_dict():
                if extra_requirement == "cookies":
                    new_extra_requirements[extra_requirement] = val
                if extra_requirement in methods_args:
                    new_extra_requirements[extra_requirement] = methods_args[
                        extra_requirement
                    ]
        extra_requirements = new_extra_requirements
        if ports is None:
            ports = extra_requirements["csrf_vuln_ports"]
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
                target=__csrf,
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
                    extra_requirements,
                ),
            )
            threads.append(t)
            t.start()
            trying += 1
            if verbose_level > 3:
                info(
                    messages(language, "trying_message").format(
                        trying, total_req, num, total, target, port, "csrf_vuln"
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
            info(messages(language, "no_vulnerability_found").format("csrf"))
            data = json.dumps(
                {
                    "HOST": target,
                    "USERNAME": "",
                    "PASSWORD": "",
                    "PORT": "",
                    "TYPE": "csrf_vuln",
                    "DESCRIPTION": messages(language, "no_vulnerability_found").format(
                        "csrf"
                    ),
                    "TIME": now(),
                    "CATEGORY": "scan",
                    "SCAN_ID": scan_id,
                    "SCAN_CMD": scan_cmd,
                }
            )
            __log_into_file(log_in_file, "a", data, language)
        os.remove(thread_tmp_filename)

    else:
        warn(messages(language, "input_target_error").format("csrf_vuln", target))
