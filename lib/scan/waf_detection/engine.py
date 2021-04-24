#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Aman Gupta, github.com/aman566

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
import logging


def extra_requirements_dict():
    return {
        "waf_scan_ports": [80, 443],
        "waf_scan_use_360": ["True"],
        "waf_scan_use_airlock": ["True"],
        "waf_scan_use_awselb": ["True"],
        "waf_scan_use_aesecure": ["True"],
        "waf_scan_use_approach": ["True"],
        "waf_scan_use_armor": ["True"],
        "waf_scan_use_arvancloud": ["True"],
        "waf_scan_use_aspnetgeneric": ["True"],
        "waf_scan_use_anquanbao": ["True"],
        "waf_scan_use_baidu": ["True"],
        "waf_scan_use_bigip": ["True"],
        "waf_scan_use_barracuda": ["True"],
        "waf_scan_use_binarysec": ["True"],
        "waf_scan_use_blockdos": ["True"],
        "waf_scan_use_cloudfront": ["True"],
        "waf_scan_use_cloudflare": ["True"],
        "waf_scan_use_cisco": ["True"],
        "waf_scan_use_comodo": ["True"],
        "waf_scan_use_dotfender": ["True"],
        "waf_scan_use_dosarrest": ["True"],
        "waf_scan_use_datapower": ["True"],
        "waf_scan_use_edgecast": ["True"],
        "waf_scan_use_expressionengine": ["True"],
        "waf_scan_use_f5asm": ["True"],
        "waf_scan_use_f5trafficshield": ["True"],
        "waf_scan_use_fortiwafsid": ["True"],
        "waf_scan_use_hyperguard": ["True"],
        "waf_scan_use_incapsula": ["True"],
        "waf_scan_use_isaserver": ["True"],
        "waf_scan_use_jiasule": ["True"],
        "waf_scan_use_keycdn": ["True"],
        "waf_scan_use_knownsec": ["True"],
        "waf_scan_use_kona": ["True"],
        "waf_scan_use_modsecurity": ["True"],
        "waf_scan_use_netcontinuum": ["True"],
        "waf_scan_use_newdefend": ["True"],
        "waf_scan_use_nsfocus": ["True"],
        "waf_scan_use_netscaler": ["True"],
        "waf_scan_use_naxsi": ["True"],
        "waf_scan_use_profense": ["True"],
        "waf_scan_use_paloalto": ["True"],
        "waf_scan_use_radware": ["True"],
        "waf_scan_use_requestvalidationmode": ["True"],
        "waf_scan_use_safe3": ["True"],
        "waf_scan_use_safedog": ["True"],
        "waf_scan_use_secureiis": ["True"],
        "waf_scan_use_sitelock": ["True"],
        "waf_scan_use_sonicwall": ["True"],
        "waf_scan_use_senginx": ["True"],
        "waf_scan_use_sophos": ["True"],
        "waf_scan_use_sucuri": ["True"],
        "waf_scan_use_stingray": ["True"],
        "waf_scan_use_teros": ["True"],
        "waf_scan_use_tencent": ["True"],
        "waf_scan_use_uspsecureentry": ["True"],
        "waf_scan_use_wallarm": ["True"],
        "waf_scan_use_watchguard": ["True"],
        "waf_scan_use_webknight": ["True"],
        "waf_scan_use_wordfence": ["True"],
        "waf_scan_use_zscaler": ["True"],
        "waf_scan_use_zenedge": ["True"],
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
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "msnbot/1.1 (+http://search.msn.com/msnbot.htm)",
]


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


def waf(
    target,
    port,
    timeout_sec,
    log_in_file,
    language,
    time_sleep,
    thread_tmp_filename,
    extra_requirements,
    socks_proxy,
    scan_id,
    scan_cmd,
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
            global waf
            headers = {
                "user-agent": random.choice(user_agent_list),
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.7,ru;q=0.3",
                "Accept-Encoding": "gzip, deflate, br",
            }
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                for i in req.headers:
                    if (
                        re.search(r"jiasule-WAF", req.headers[i], re.IGNORECASE)
                        or re.search(r"__jsluid", req.headers[i], re.IGNORECASE)
                        or re.search(r"jsl_tracking", req.headers[i], re.IGNORECASE)
                        or re.search(
                            r"static\.jiasule\.com/static/js/http_error\.js",
                            req.text,
                            re.IGNORECASE,
                        )
                        or (
                            req.status_code == 403
                            and "notice-jiasule" in req.text.lower()
                        )
                        and extra_requirements["waf_scan_use_jiasule"][0]
                    ):
                        waf = "Jiasule Web Application Firewall (Jiasule) Detected!!"
                        return True
            except Exception:
                pass
            try:
                req = requests.get(
                    target, timeout=timeout_sec, headers=headers, verify=False
                )
                if (
                    re.match("^(cloudflare|__cfduid)=", req.headers["set-cookie"])
                    and extra_requirements["waf_scan_use_cloudflare"][0]
                ):
                    waf = "Cloudflare Detected!!"
                    return True
            except Exception:
                pass
            try:
                req = requests.get(
                    target, timeout=timeout_sec, headers=headers, verify=False
                )
                if (
                    re.match(
                        "^AL[_-](SESS|LB)(-S)?=",
                        req.headers["set-cookie"],
                        re.IGNORECASE,
                    )
                    and extra_requirements["waf_scan_use_airlock"][0]
                ):
                    waf = "AirLock Detected!!"
                    return True
            except Exception:
                pass
            try:
                req = requests.get(
                    target, timeout=timeout_sec, headers=headers, verify=False
                )
                if (
                    re.match(
                        "^(incap_ses|visid_incap)=",
                        req.headers["set-cookie"],
                        re.IGNORECASE,
                    )
                    and extra_requirements["waf_scan_use_incapsula"][0]
                ):
                    waf = "Imperva Incapsula Detected!!"
                    return True
            except Exception:
                pass
            try:
                req = requests.get(
                    target, timeout=timeout_sec, headers=headers, verify=False
                )
                if (
                    re.match(".*PLBSID=.*", req.headers["set-cookie"], re.IGNORECASE)
                    or "profense" in req.headers["server"].lower()
                ) and extra_requirements["waf_scan_use_profense"][0]:
                    waf = "Profense Detected!!"
                    return True
            except Exception:
                pass
            try:
                req = requests.get(
                    target, timeout=timeout_sec, headers=headers, verify=False
                )
                if (
                    re.match(".*ODSESSION.*", req.headers["set-cookie"], re.IGNORECASE)
                    and extra_requirements["waf_scan_use_hyperguard"][0]
                ):
                    waf = "HyperGuard Detected!!"
                    return True
            except Exception:
                pass
            try:
                req = requests.get(
                    target, timeout=timeout_sec, headers=headers, verify=False
                )
                if (
                    re.match(
                        ".*barra_counter_session.*",
                        req.headers["set-cookie"],
                        re.IGNORECASE,
                    )
                    and extra_requirements["waf_scan_use_barracuda"][0]
                ):
                    waf = "Barracuda Detected!!"
                    return True
                for i in req.headers:
                    if (
                        "barracuda_" in i
                        and extra_requirements["waf_scan_use_barracuda"][0]
                    ):
                        waf = "Barracuda Detected!!"
                        return True
            except Exception:
                pass
            try:
                req = requests.get(
                    target, timeout=timeout_sec, headers=headers, verify=False
                )
                for i in req.headers:
                    if (
                        "X-dotdefender-denied" in i
                        and extra_requirements["waf_scan_use_dotfender"][0]
                    ):
                        waf = "Dotdefender Detected!!"
                        return True
            except Exception:
                pass
            try:
                req = requests.get(
                    target, timeout=timeout_sec, headers=headers, verify=False
                )
                if (
                    re.match(
                        "^(asm|ts).?([a-zA-Z0-9]{8,11})?.*",
                        req.headers["set-cookie"],
                        re.IGNORECASE,
                    )
                    and extra_requirements["waf_scan_use_f5asm"][0]
                ):
                    waf = "F5 ASM Detected!!"
                    return True
            except Exception:
                pass
            try:
                req = requests.get(
                    target, timeout=timeout_sec, headers=headers, verify=False
                )
                if (
                    re.match(".*ASINFO=.*", req.headers["set-cookie"], re.IGNORECASE)
                    or "F5-TrafficShield" in req.headers["server"]
                ) and extra_requirements["waf_scan_use_f5trafficshield"][0]:
                    waf = "F5-TrafficShield Detected!!"
                    return True
            except Exception:
                pass
            try:
                req = requests.get(
                    target, timeout=timeout_sec, headers=headers, verify=False
                )
                if (
                    re.match(".*st8id=.*", req.headers["set-cookie"], re.IGNORECASE)
                    and extra_requirements["waf_scan_use_teros"][0]
                ):
                    waf = "Teros Detected!!"
                    return True
            except Exception:
                pass
            try:
                req = requests.get(
                    target, timeout=timeout_sec, headers=headers, verify=False
                )
                if (
                    re.match(
                        ".*NCI__SessionId=.*", req.headers["set-cookie"], re.IGNORECASE
                    )
                    and extra_requirements["waf_scan_use_netcontinuum"][0]
                ):
                    waf = "Netcontinuum Detected!!"
                    return True
            except Exception:
                pass
            try:
                req = requests.get(
                    target, timeout=timeout_sec, headers=headers, verify=False
                )
                if (
                    re.match(
                        r"This response was generated by Wordfence|Generated by Wordfence|A potentially unsafe operation has been detected in your request to this site|Your access to this site has been limited",
                        req.text,
                        re.IGNORECASE,
                    )
                    and extra_requirements["waf_scan_use_wordfence"][0]
                ):
                    waf = "Wordfence (Feedjit) Detected!!"
                    return True
            except Exception:
                pass
            try:
                req = requests.get(
                    target, timeout=timeout_sec, headers=headers, verify=False
                )
                if (
                    "binarysec" in req.headers["server"]
                    and extra_requirements["waf_scan_use_binarysec"][0]
                ):
                    waf = "BinarySec Detected!!"
                    return True
            except Exception:
                pass
            try:
                req = requests.get(
                    target, timeout=timeout_sec, headers=headers, verify=False
                )
                if (
                    "nginx-wallarm" in req.headers["server"]
                    and extra_requirements["waf_scan_use_wallarm"][0]
                ):
                    waf = "Wallarm Web Application Firewall (Wallarm) Detected!!"
                    return True
            except Exception:
                pass
            try:
                req = requests.get(
                    target, timeout=timeout_sec, headers=headers, verify=False
                )
                if (
                    re.match(".*AWSALB.*", req.headers["set-cookie"], re.IGNORECASE)
                    and extra_requirements["waf_scan_use_awselb"][0]
                ):
                    waf = "AWS ELB Detected!!"
                    return True
                for i in req.headers:
                    if "x-amz" in i.lower():
                        waf = "AWS ELB Detected!!"
                        return True
            except Exception:
                pass
            try:
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                for i in req.headers:
                    if i.lower().startswith("ar-"):
                        waf = "Arvan Cloud Web Application Firewall Detected!!"
                        return True
                if (
                    req.headers["server"].lower().startswith("arvan")
                    and extra_requirements["waf_scan_use_arvancloud"][0]
                ):
                    waf = "Arvan Cloud Web Application Firewall Detected!!"
                    return True
            except Exception:
                pass
            try:
                req = requests.get(
                    target, timeout=timeout_sec, headers=headers, verify=False
                )
                if (
                    "blockdos.net" in req.headers["server"].lower()
                    and extra_requirements["waf_scan_use_blockdos"][0]
                ):
                    waf = "BlockDOS Web Application Firewall Detected!!"
                    return True
            except Exception:
                pass
            try:
                req = requests.get(
                    target, timeout=timeout_sec, headers=headers, verify=False
                )
                if (
                    req.status_code in [403, 500]
                    and re.search(
                        r"\AX-Mapping", req.headers["set-cookie"], re.IGNORECASE
                    )
                    and extra_requirements["waf_scan_use_stingray"][0]
                ):
                    waf = (
                        "Stingray Application Firewall (Riverbed / Brocade) Detected!!"
                    )
                    return True
            except Exception:
                pass
            try:
                temp = target
                target += "/<script>alert(1)</script>"
                req = requests.get(
                    target, headers=headers, verify=False, timeout=timeout_sec
                )
                if (
                    req.status_code == 493
                    or "wangshan.360.cn" in req.text.lower()
                    or "qianxin-waf" in req.headers["server"].lower()
                    or req.headers["X-Powered-By-360WZB"]
                ) and extra_requirements["waf_scan_use_360"][0]:
                    waf = "360 Web Application Firewall Detected!!"
                    return True
                print("aman")
            except Exception:
                pass
            target = temp
            try:
                req = requests.get(
                    target, headers=headers, verify=False, timeout=timeout_sec
                )
                if (
                    "miss" in req.headers["x-powered-by-anquanbao"].lower()
                    or "/aqb_cc/error/" in req.text.lower()
                ) and extra_requirements["waf_scan_use_anquanbao"][0]:
                    waf = "Anquanbao Web Application Firewall Detected!!"
                    return True
            except Exception:
                pass
            try:
                req = requests.get(
                    target, headers=headers, verify=False, timeout=timeout_sec
                )
                if (
                    "x-backside-transport" in str(req.headers).lower()
                    and extra_requirements["waf_scan_use_datapower"][0]
                ):
                    waf = "Datapower Web Application Firewall Detected!!"
                    return True
            except Exception:
                pass
            try:
                req = requests.get(
                    target, headers=headers, verify=False, timeout=timeout_sec
                )
                if (
                    "x-sl-compstate" in str(req.headers).lower()
                    or re.search(
                        r"Unauthorized Activity Has Been Detected.+Case Number:",
                        req.text,
                        re.IGNORECASE,
                    )
                ) and extra_requirements["waf_scan_use_radware"][0]:
                    waf = "AppWall (Radware) Application Firewall Detected!!"
                    return True
            except Exception:
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, headers=headers, verify=False, timeout=timeout_sec
                )
                if (
                    req.headers["server"].lower().startswith("zscaler")
                    or "img_logo_new1.png" in req.text.lower()
                ) and extra_requirements["waf_scan_use_zscaler"][0]:
                    waf = "Zscaler Web Application Firewall Detected!!"
                    return True
            except Exception:
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, headers=headers, verify=False, timeout=timeout_sec
                )
                if (
                    "approach" in req.headers["server"].lower()
                    and extra_requirements["waf_scan_use_approach"][0]
                ):
                    waf = "Approach Web Application Firewall Detected!!"
                    return True
            except Exception:
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, headers=headers, verify=False, timeout=timeout_sec
                )
                if (
                    "yunjiasu" in req.headers["server"].lower()
                    and extra_requirements["waf_scan_use_baidu"][0]
                ):
                    waf = "Baidu Web Application Firewall Detected!!"
                    return True
            except Exception:
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, timeout=timeout_sec, headers=headers
                )
                if (
                    "x-amz-cf-id" in str(req.headers).lower()
                    or "cloudfront" in req.headers["server"].lower()
                    or re.search(r"cloudfront", req.headers["X-Cache"].lower(), re.I)
                ) and extra_requirements["waf_scan_use_cloudfront"][0]:
                    waf = "Cloudfront Web Application Firewall Detected!!"
                    return True
            except Exception:
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, timeout=timeout_sec, headers=headers
                )
                if (
                    "x-wa-info" in str(req.headers).lower()
                    or "x-cnection" in str(req.headers).lower()
                    and extra_requirements["waf_scan_use_bigip"][0]
                ):
                    waf = " BIG-IP ASM Web Application Firewall Detected"
                    return True
            except Exception:
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, headers=headers, verify=False, timeout=timeout_sec
                )
                if (
                    "this request has been blocked by website protection from armor"
                    in req.text.lower()
                    and extra_requirements["waf_scan_use_armor"][0]
                ):
                    waf = "Armor Web Application Firewall Detected!!"
                    return True
            except Exception:
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, headers=headers, verify=False, timeout=timeout_sec
                )
                for i in req.headers:
                    if i.lower() == "x-aspnet-version":
                        waf = " ASP.NET Generic Web Application Firewall Detected"
                        return True
                if (
                    "asp.net" in req.headers["x-powered-by"].lower()
                    and extra_requirements["waf_scan_use_aspnetgeneric"][0]
                ):
                    waf = " ASP.NET Generic Web Application Firewall Detected"
                    return True
            except Exception:
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, headers=headers, verify=False, timeout=timeout_sec
                )
                if (
                    "aesecure_denied.png" in req.text.lower()
                    and extra_requirements["waf_scan_use_aesecure"][0]
                ):
                    waf = "aeSecure Web Application Firewall Detected!!"
                    return True
            except Exception:
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                if (
                    req.headers["server"].lower().startswith("keycdn")
                    and extra_requirements["waf_scan_use_keycdn"][0]
                ):
                    waf = "KeyCDN Web Application Firewall Detected!!"
                    return True
            except Exception:
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                if (
                    "x-zen-fury" in req.headers
                    or req.headers["server"].lower().startswith("zenedge")
                ) and extra_requirements["waf_scan_use_zscaler"][0]:
                    waf = "ZenEdge Web Application Firewall Detected!!"
                    return True
            except Exception:
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                if (
                    "protected by comodo waf" in req.headers["server"].lower()
                    and extra_requirements["waf_scan_use_comodo"][0]
                ):
                    waf = "COMODO Web Application Firewall Detected!!"
                    return True
            except Exception:
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                if (
                    "ace xml gateway" in req.headers["server"].lower()
                    and extra_requirements["waf_scan_use_cisco"][0]
                ):
                    waf = "CISCO ACE XML Gateway (Cisco System) Firewall Detected!!"
                    return True
            except Exception:
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                if (
                    re.search(r"dosarrest", req.headers["server"], re.IGNORECASE)
                    and extra_requirements["waf_scan_use_dosarrest"][0]
                ):
                    waf = "DOSarrest (DOSarrest Internet Security) Firewall Detected!!"
                    return True
            except Exception:
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                if (
                    re.search(r"ecdf", req.headers["server"], re.IGNORECASE)
                    and extra_requirements["waf_scan_use_edgecast"][0]
                ):
                    waf = "ECDF (DOSarrest Internet Security) Firewall Detected!!"
                    return True
            except Exception:
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                if (
                    re.search(r"invalid get data", req.text.lower(), re.IGNORECASE)
                    and extra_requirements["waf_scan_use_expressionengine"][0]
                ):
                    waf = "ExpressionEngine (EllisLab) Firewall Detected!!"
                    return True
            except Exception:
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                if (
                    re.search(r"/ks-waf-error\.png", req.text.lower(), re.IGNORECASE)
                    and extra_requirements["waf_scan_use_knownsec"][0]
                ):
                    waf = "KS-WAF (Knownsec) Firewall Detected!!"
                    return True
            except Exception:
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                for i in req.headers:
                    if i.lower() == "set-cookie":
                        if (
                            re.search(r"FORTIWAFSID=", req.headers[i], re.IGNORECASE)
                            and extra_requirements["waf_scan_use_fortiwafsid"][0]
                        ):
                            waf = "FortiWeb (Fortinet) Web Application Firewall Detected!!"
                            return True
                for i in [".fgd_icon", ".blocked", ".authenticate"]:
                    if i in req.text.lower():
                        waf = "FortiWeb (Fortinet) Web Application Firewall Detected!!"
                        return True
            except Exception:
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                for i in [
                    "SiteLock Incident ID",
                    "sitelock-site-verification",
                    "sitelock_shield_logo",
                ]:
                    if (
                        i.lower() in req.text.lower()
                        and extra_requirements["waf_scan_use_sitelock"][0]
                    ):
                        waf = (
                            "TrueShield Web Application Firewall (SiteLock) Detected!!"
                        )
                        return True
            except Exception:
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                for i in [
                    "The ISA Server denied the specified Uniform Resource Locator (URL)",
                    "he server denied the specified Uniform Resource Locator (URL). Contact the server administrator",
                ]:
                    if (
                        i.lower() in req.text.lower()
                        and extra_requirements["waf_scan_use_isaserver"][0]
                    ):
                        waf = (
                            "ISA Server (Microsoft) Web Application Firewall Detected!!"
                        )
                        return True
            except Exception:
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                if (
                    (
                        req.status_code in [400, 403, 501]
                        and re.search(r"Reference #[0-9a-f.]+", req.text, re.IGNORECASE)
                    )
                    or re.search(r"akamaighost", req.headers["server"], re.IGNORECASE)
                ) and extra_requirements["waf_scan_use_kona"][0]:
                    waf = "KONA Security Solutions (Akamai Technologies) Web Application Firewall Detected!!"
                    return True
            except Exception:
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                if (
                    "this error was generated by mod_security" in req.text.lower()
                    or re.search(
                        r"Mod_Security|NOYB", req.headers["server"], re.IGNORECASE
                    )
                    and extra_requirements["waf_scan_use_modsecurity"][0]
                ):
                    waf = "ModSecurity: Open Source Web Application Firewall (Trustwave) Detected!!"
                    return True
            except Exception:
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                if (
                    "newdefend" == req.headers["server"].lower()
                    and extra_requirements["waf_scan_use_newdefend"][0]
                ):
                    waf = "Newdefend Web Application Firewall Detected!!"
                    return True
            except Exception:
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                if (
                    "nsfocus" == req.headers["server"].lower()
                    and extra_requirements["waf_scan_use_nsfocus"][0]
                ):
                    waf = "NSFOCUS Web Application Firewall Detected!!"
                    return True
            except Exception:
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                if (
                    re.search(
                        r"has been blocked in accordance with company policy|Virus/Spyware Download Blocked|Palo Alto Next Generation Security Platform",
                        req.text,
                        re.IGNORECASE,
                    )
                    and extra_requirements["waf_scan_use_paloalto"][0]
                ):
                    waf = "Palo Alto Firewall (Palo Alto Networks) Detected!!"
                    return True
            except Exception:
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                if (
                    re.search(r"sonicwall", req.headers["server"], re.IGNORECASE)
                    and extra_requirements["waf_scan_use_sonicwall"][0]
                ):
                    waf = "SonicWALL (Dell) Detected!!"
                    return True
            except Exception:
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                if (
                    req.headers["x-data-origin"].lower().startswith("naxsi")
                    and extra_requirements["waf_scan_use_naxsi"][0]
                ):
                    waf = "NAXSI (NBS System) Web Application Firewall Detected!!"
                    return True
            except Exception:
                # logging.exception("message")
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                if (
                    req.status_code == 999
                    or req.headers["server"].lower() == "webknight"
                ) and extra_requirements["waf_scan_use_webknight"][0]:
                    waf = "WebKnight Application Firewall (AQTRONIX) Detected!!"
                    return True
            except Exception:
                # logging.exception("message")
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                if (
                    re.search(
                        r"Secure Entry Server", req.headers["server"], re.IGNORECASE
                    )
                    and extra_requirements["waf_scan_use_uspsecureentry"][0]
                ):
                    waf = (
                        "USP Secure Entry Server (United Security Providers) Detected!!"
                    )
                    return True
            except Exception:
                # logging.exception("message")
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                if (
                    re.search(r"Safe3WAF", req.headers["x-powered-by"], re.IGNORECASE)
                    or re.search(
                        r"Safe3 Web Firewall", req.headers["server"], re.IGNORECASE
                    )
                ) and extra_requirements["waf_scan_use_safe3"][0]:
                    waf = "Safe3 Web Application Firewall Detected!!"
                    return True
            except Exception:
                # logging.exception("message")
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                if (
                    req.status_code == 403
                    and re.search(r"waf.tencent-cloud.com", req.text, re.IGNORECASE)
                ) and extra_requirements["waf_scan_use_tencent"][0]:
                    waf = "Tencent Cloud Web Application Firewall (Tencent Cloud Computing) Detected!!"
                    return True
            except Exception:
                # logging.exception("message")
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                if (
                    re.search(r"Powered by UTM Web Protection", req.text, re.IGNORECASE)
                    and extra_requirements["waf_scan_use_sophos"][0]
                ):
                    waf = "UTM Web Protection (Sophos) Detected!!"
                    return True
            except Exception:
                # logging.exception("message")
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                if (
                    re.search(r"\AWatchGuard", req.headers["server"], re.IGNORECASE)
                    and extra_requirements["waf_scan_use_watchguard"][0]
                ):
                    waf = "WatchGuard (WatchGuard Technologies) Detected!!"
                    return True
            except Exception:
                # logging.exception("message")
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                if (
                    re.search(r"WAF/2\.0", req.headers["x-powered-by"], re.IGNORECASE)
                    or re.search(r"Safedog", req.headers["server"], re.IGNORECASE)
                    or re.search(r"safedog", req.headers["set-cookie"], re.IGNORECASE)
                ) and extra_requirements["waf_scan_use_safedog"][0]:
                    waf = "Safedog Web Application Firewall Detected!!"
                    return True
            except Exception:
                # logging.exception("message")
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                if (
                    re.search(
                        r"SecureIIS[^<]+Web Server Protection|http://www.eeye.com/SecureIIS/|SecureIIS Error",
                        req.text,
                        re.IGNORECASE,
                    )
                    and extra_requirements["waf_scan_use_secureiis"][0]
                ):
                    waf = "SecureIIS Web Server Security (BeyondTrust) Detected!!"
                    return True
            except Exception:
                # logging.exception("message")
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                if (
                    re.search(r"SENGINX-ROBOT-MITIGATION", req.text, re.IGNORECASE)
                    and extra_requirements["waf_scan_use_senginx"][0]
                ):
                    waf = "SEnginx (Neusoft Corporation) Detected!!"
                    return True
            except Exception:
                # logging.exception("message")
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                if (
                    re.search(
                        r"Sucuri/Cloudproxy", req.headers["server"], re.IGNORECASE
                    )
                    or re.search(
                        r"Access Denied - Sucuri Website Firewall|https://sucuri.net/privacy-policy|cloudproxy@sucuri.net",
                        req.text,
                        re.IGNORECASE,
                    )
                    or re.search("X-Sucuri-ID", str(req.headers), re.IGNORECASE)
                ) and extra_requirements["waf_scan_use_sucuri"][0]:
                    waf = "CloudProxy WebSite Firewall (Sucuri) Detected!!"
                    return True
            except Exception:
                # logging.exception("message")
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                if (
                    re.search(
                        r"ASP.NET has detected data in the request that is potentially dangerous|Request Validation has detected a potentially dangerous client input value",
                        req.text,
                        re.IGNORECASE,
                    )
                    or (
                        req.status_code == 500
                        and "HttpRequestValidationException" in req.text.lower()
                    )
                ) and extra_requirements["waf_scan_use_requestvalidationmode"][0]:
                    waf = "ASP.NET RequestValidationMode (Microsoft) Web Application Firewall Detected!!"
                    return True
            except Exception:
                # logging.exception("message")
                pass
            try:
                time.sleep(0.01)
                req = requests.get(
                    target, verify=False, headers=headers, timeout=timeout_sec
                )
                for i in req.headers:
                    if i.lower() == "set-cookie":
                        if (
                            re.search(
                                r"ns_af=|citrix_ns_id|NSC_",
                                req.headers["set-cookie"],
                                re.IGNORECASE,
                            )
                            and extra_requirements["waf_scan_use_netscaler"][0]
                        ):
                            waf = "NetScaler (Citrix Systems) Web Application Firewall Detected!!"
                            return True
                    if (
                        i.lower() in ["cneonction", "nncoection"]
                        and extra_requirements["waf_scan_use_netscaler"][0]
                    ):
                        waf = "NetScaler (Citrix Systems) Web Application Firewall Detected!!"
                        return True
                    if i.lower() == "via":
                        if (
                            re.search(r"NS-CACHE", req.headers[i])
                            and extra_requirements["waf_scan_use_netscaler"][0]
                        ):
                            waf = "NetScaler (Citrix Systems) Web Application Firewall Detected!!"
                            return True
            except Exception:
                # logging.exception("message")
                return False
    except Exception:
        # some error warning
        return False


def __waf(
    target,
    port,
    timeout_sec,
    log_in_file,
    language,
    time_sleep,
    thread_tmp_filename,
    extra_requirements,
    socks_proxy,
    scan_id,
    scan_cmd,
):
    if waf(
        target,
        port,
        timeout_sec,
        log_in_file,
        language,
        time_sleep,
        thread_tmp_filename,
        extra_requirements,
        socks_proxy,
        scan_id,
        scan_cmd,
    ):
        info(messages(language, "waf_detected").format(waf))
        __log_into_file(thread_tmp_filename, "w", "0", language)
        data = json.dumps(
            {
                "HOST": target,
                "USERNAME": "",
                "PASSWORD": "",
                "PORT": port,
                "TYPE": "waf_scan",
                "DESCRIPTION": messages(language, "waf_detected").format(waf),
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
            ports = extra_requirements["waf_scan_ports"]
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
                target=__waf,
                args=(
                    target,
                    int(port),
                    timeout_sec,
                    log_in_file,
                    language,
                    time_sleep,
                    thread_tmp_filename,
                    extra_requirements,
                    socks_proxy,
                    scan_id,
                    scan_cmd,
                ),
            )
            threads.append(t)
            t.start()
            trying += 1
            if verbose_level > 3:
                info(
                    messages(language, "trying_message").format(
                        trying, total_req, num, total, target, port, "waf_scan"
                    )
                )
            while 1:
                try:
                    if threading.activeCount() >= thread_number:
                        time.sleep(1)
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
            time.sleep(1)
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
                    "TYPE": "waf_scan",
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
        warn(messages(language, "input_target_error").format("waf_scan", target))
