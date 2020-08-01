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
import ssl
from core.alert import *
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.log import __log_into_file
import requests


def extra_requirements_dict():
    return {
        "sub_takeover_vuln_ports": [80, 443],
        "sub_takeover_aws": ["The specified bucket does not exist"],
        "sub_takeover_bitbucket": ["Repository not found"],
        "sub_takeover_github": ["There isn't a Github Pages site here."],
        "sub_takeover_shopify": ["Sorry, this shop is currently unavailable."],
        "sub_takeover_fastly": ["Fastly error: unknown domain:"],
        "sub_takeover_feedPress": ["The feed has not been found."],
        "sub_takeover_ghost": [
            "The thing you were looking for is no longer here, or never was"
        ],
        "sub_takeover_heroku": [
            "no-such-app.html|<title>no such app</title>|herokucdn.com/error-pages/no-such-app.html"
        ],
        "sub_takeover_pantheon": [
            "The gods are wise, but do not know of the site which you seek."
        ],
        "sub_takeover_tumblr": [
            "Whatever you were looking for doesn't currently exist at this address."
        ],
        "sub_takeover_wordpress": ["Do you want to register"],
        "sub_takeover_teamWork": ["Oops - We didn't find your site."],
        "sub_takeover_helpjuice": ["We could not find what you're looking for."],
        "sub_takeover_helpscout": ["No settings were found for this company:"],
        "sub_takeover_cargo": ["<title>404 &mdash; File not found</title>"],
        "sub_takeover_statusPage": [
            'You are being <a href="https://www.statuspage.io">redirected'
        ],
        "sub_takeover_uservoice": ["This UserVoice subdomain is currently available!"],
        "sub_takeover_surge": ["project not found"],
        "sub_takeover_intercom": [
            "This page is reserved for artistic dogs.|Uh oh. That page doesn't exist</h1>"
        ],
        "sub_takeover_webflow": [
            '<p class="description">The page you are looking for doesn\'t exist or has been moved.</p>'
        ],
        "sub_takeover_kajabi": [
            "<h1>The page you were looking for doesn't exist.</h1>"
        ],
        "sub_takeover_thinkific": [
            "You may have mistyped the address or the page may have moved."
        ],
        "sub_takeover_tave": ["<h1>Error 404: Page Not Found</h1>"],
        "sub_takeover_wishpond": ["<h1>https://www.wishpond.com/404?campaign=true"],
        "sub_takeover_aftership": [
            "Oops.</h2><p class=\"text-muted text-tight\">The page you're looking for doesn't exist."
        ],
        "sub_takeover_aha": ["There is no portal here ... sending you back to Aha!"],
        "sub_takeover_tictail": [
            'to target URL: <a href="https://tictail.com|Start selling on Tictail.'
        ],
        "sub_takeover_brightcove": [
            '<p class="bc-gallery-error-code">Error Code: 404</p>'
        ],
        "sub_takeover_bigcartel": ["<h1>Oops! We couldn&#8217;t find that page.</h1>"],
        "sub_takeover_activeCampaign": ['alt="LIGHTTPD - fly light."'],
        "sub_takeover_campaignmonitor": [
            'Double check the URL or <a href="mailto:help@createsend.com'
        ],
        "sub_takeover_acquia": [
            "The site you are looking for could not be found.|If you are an Acquia Cloud customer and expect to see your site at this address"
        ],
        "sub_takeover_proposify": [
            'If you need immediate assistance, please contact <a href="mailto:support@proposify.biz"'
        ],
        "sub_takeover_simplebooklet": [
            "We can't find this <a href=\"https://simplebooklet.com"
        ],
        "sub_takeover_getResponse": [
            "With GetResponse Landing Pages, lead generation has never been easier"
        ],
        "sub_takeover_vend": ["Looks like you've traveled too far into cyberspace."],
        "sub_takeover_jetbrains": ["is not a registered InCloud YouTrack."],
        "sub_takeover_smartling": ["Domain is not configured"],
        "sub_takeover_pingdom": ["pingdom"],
        "sub_takeover_tilda": ["Domain has been assigned"],
        "sub_takeover_surveygizmo": ["data-html-name"],
        "sub_takeover_mashery": ["Unrecognized domain <strong>"],
        "sub_takeover_divio": ["Application not responding"],
        "sub_takeover_airee": ["Ошибка 402. Сервис Айри.рф не оплачен"],
        "sub_takeover_anima": [
            "If this is your website and you've just created it, try refreshing in a minute"
        ],
        "sub_takeover_hatenablog": ["404 Blog is not found"],
        "sub_takeover_kinsta": ["No Site For Domain"],
        "sub_takeover_launchrock": [
            "It looks like you may have taken a wrong turn somewhere. Don't worry...it happens to all of us."
        ],
        "sub_takeover_ngrok": ["Tunnel *.ngrok.io not found"],
        "sub_takeover_unbounce": ["The requested URL was not found on this server."],
        "sub_takeover_readme": ["Project doesnt exist... yet!"],
        "sub_takeover_smartjobboard": [
            "This job board website is either expired or its domain name is invalid."
        ],
        "sub_takeover_strikingly": ["page not found"],
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
    except Exception as e:
        return None


def sub_takeover(
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
    extra_requirement,
):
    try:
        s = conn(target, port, timeout_sec, socks_proxy)
        if not s:
            return False
        else:
            if target_type(target) != "HTTP" and port == 443:
                target = "https://" + target
            if target_type(target) != "HTTP" and port == 80:
                target = "http://" + target
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome 63.0.3239.132 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml; q=0.9,image/webp,image/apng,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
            }
            req = requests.get(
                target, headers=headers, verify=False, timeout=timeout_sec
            )
            for key, value in extra_requirement.items():
                if (
                    key != "sub_takeover_vuln_ports"
                    and value[0].lower() in req.text.lower()
                ):
                    return True
            return False
    except Exception as e:
        # some error warning
        return False


def __sub_takeover(
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
    extra_requirement,
):
    if sub_takeover(
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
        extra_requirement,
    ):
        info(
            messages(language, "target_vulnerable").format(
                target,
                port,
                "Subdomain Takeover Vulnerability found which will allow an adversary to claim and take control of the victim’s subdomain.",
            )
        )
        __log_into_file(thread_tmp_filename, "w", "0", language)
        data = json.dumps(
            {
                "HOST": target,
                "USERNAME": "",
                "PASSWORD": "",
                "PORT": port,
                "TYPE": "subomain_takeover_vuln",
                "DESCRIPTION": messages(language, "vulnerable").format(
                    "Subdomain Takeover Vulnerability found which will allow an adversary to claim and take control of the victim’s subdomain."
                ),
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
            for extra_requirement in extra_requirements_dict():
                if extra_requirement in methods_args:
                    new_extra_requirements[extra_requirement] = methods_args[
                        extra_requirement
                    ]
        extra_requirements = new_extra_requirements
        if ports is None:
            ports = extra_requirements["sub_takeover_vuln_ports"]
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
                target=__sub_takeover,
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
                        trying,
                        total_req,
                        num,
                        total,
                        target,
                        port,
                        "subdomain_takeover_vuln",
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
        kill_time = int(timeout_sec / 0.1) if int(timeout_sec / 0.1) is not 0 else 1
        while 1:
            time.sleep(0.1)
            kill_switch += 1
            try:
                if threading.activeCount() is 1 or kill_switch is kill_time:
                    break
            except KeyboardInterrupt:
                break
        thread_write = int(open(thread_tmp_filename).read().rsplit()[0])
        if thread_write is 1 and verbose_level is not 0:
            info(
                messages(language, "no_vulnerability_found").format(
                    "Subdomain Takeover"
                )
            )
            data = json.dumps(
                {
                    "HOST": target,
                    "USERNAME": "",
                    "PASSWORD": "",
                    "PORT": "",
                    "TYPE": "subdomain_takeover_vuln",
                    "DESCRIPTION": messages(language, "no_vulnerability_found").format(
                        "Subdomain Takeover"
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
        warn(
            messages(language, "input_target_error").format(
                "subdomain_takeover_vuln", target
            )
        )
