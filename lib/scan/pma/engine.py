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
from core.alert import *
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from lib.icmp.engine import do_one as do_one_ping
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.log import __log_into_file


def extra_requirements_dict():
    return {
        "pma_scan_http_method": ["GET"],
        "pma_scan_random_agent": ["True"],
        "pma_scan_list": ['/admin/', '/accounts/login/', '/admin1.php/', '/admin.php/',
                          '/admin.html/', '/admin1.php/', '/admin1.html/', '/login.php/', '/admin/cp.php/', '/cp.php/',
                          '/administrator/index.php/', '/administrator/index.html/', '/administartor/', '/admin.login/',
                          '/administrator/login.php/', '/administrator/login.html/', '/phpMyAdmin/', '/phpmyadmin/',
                          '/PMA/', '/pma/', '/dbadmin/', '/mysql/', '/myadmin/', '/phpmyadmin2/', '/phpMyAdmin2/',
                          '/phpMyAdmin-2/', '/php-my-admin/', '/phpMyAdmin-2.2.3/', '/phpMyAdmin-2.2.6/',
                          '/phpMyAdmin-2.5.1/', '/phpMyAdmin-2.5.4/', '/phpMyAdmin-2.5.5-rc1/',
                          '/phpMyAdmin-2.5.5-rc2/', '/phpMyAdmin-2.5.5/', '/phpMyAdmin-2.5.5-pl1/',
                          '/phpMyAdmin-2.5.6-rc1/', '/phpMyAdmin-2.5.6-rc2/', '/phpMyAdmin-2.5.6/',
                          '/phpMyAdmin-2.5.7/', '/phpMyAdmin-2.5.7-pl1/', '/phpMyAdmin-2.6.0-alpha/',
                          '/phpMyAdmin-2.6.0-alpha2/', '/phpMyAdmin-2.6.0-beta1/', '/phpMyAdmin-2.6.0-beta2/',
                          '/phpMyAdmin-2.6.0-rc1/', '/phpMyAdmin-2.6.0-rc2/', '/phpMyAdmin-2.6.0-rc3/',
                          '/phpMyAdmin-2.6.0/', '/phpMyAdmin-2.6.0-pl1/', '/phpMyAdmin-2.6.0-pl2/',
                          '/phpMyAdmin-2.6.0-pl3/', '/phpMyAdmin-2.6.1-rc1/', '/phpMyAdmin-2.6.1-rc2/',
                          '/phpMyAdmin-2.6.1/', '/phpMyAdmin-2.6.1-pl1/', '/phpMyAdmin-2.6.1-pl2/',
                          '/phpMyAdmin-2.6.1-pl3/', '/phpMyAdmin-2.6.2-rc1/', '/phpMyAdmin-2.6.2-beta1/',
                          '/phpMyAdmin-2.6.2-rc1/', '/phpMyAdmin-2.6.2/', '/phpMyAdmin-2.6.2-pl1/',
                          '/phpMyAdmin-2.6.3/', '/phpMyAdmin-2.6.3-rc1/', '/phpMyAdmin-2.6.3/',
                          '/phpMyAdmin-2.6.3-pl1/', '/phpMyAdmin-2.6.4-rc1/', '/phpMyAdmin-2.6.4-pl1/',
                          '/phpMyAdmin-2.6.4-pl2/', '/phpMyAdmin-2.6.4-pl3/', '/phpMyAdmin-2.6.4-pl4/',
                          '/phpMyAdmin-2.6.4/', '/phpMyAdmin-2.7.0-beta1/', '/phpMyAdmin-2.7.0-rc1/',
                          '/phpMyAdmin-2.7.0-pl1/', '/phpMyAdmin-2.7.0-pl2/', '/phpMyAdmin-2.7.0/',
                          '/phpMyAdmin-2.8.0-beta1/', '/phpMyAdmin-2.8.0-rc1/', '/phpMyAdmin-2.8.0-rc2/',
                          '/phpMyAdmin-2.8.0/', '/phpMyAdmin-2.8.0.1/', '/phpMyAdmin-2.8.0.2/', '/phpMyAdmin-2.8.0.3/',
                          '/phpMyAdmin-2.8.0.4/', '/phpMyAdmin-2.8.1-rc1/', '/phpMyAdmin-2.8.1/', '/phpMyAdmin-2.8.2/',
                          '/sqlmanager/', '/mysqlmanager/', '/p/m/a/', '/PMA2005/', '/pma2005/', '/phpmanager/',
                          '/php-myadmin/', '/phpmy-admin/', '/webadmin/', '/sqlweb/', '/websql/',
                          '/webdb/', '/mysqladmin/', '/mysql-admin/', '/mya/']
    }


def check(target, user_agent, timeout_sec, log_in_file, language, time_sleep, thread_tmp_filename, retries,
          http_method, socks_proxy, scan_id, scan_cmd):
    status_codes = [200, 401, 403]
    time.sleep(time_sleep)
    try:
        if socks_proxy is not None:
            socks_version = socks.SOCKS5 if socks_proxy.startswith('socks5://') else socks.SOCKS4
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
                socks.set_default_proxy(socks_version, str(socks_proxy.rsplit(':')[0]), int(socks_proxy.rsplit(':')[1]))
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo
        n = 0
        while 1:
            try:
                if http_method == "GET":
                    r = requests.get(target, timeout=timeout_sec, headers=user_agent)
                elif http_method == "HEAD":
                    r = requests.head(target, timeout=timeout_sec, headers=user_agent)
                content = r.content
                break
            except:
                n += 1
                if n is retries:
                    warn(messages(language,"http_connection_timeout").format(target))
                    return 1
        if r.status_code in status_codes:
            info(messages(language,"found").format(target, r.status_code, r.reason))
            __log_into_file(thread_tmp_filename, 'w', '0', language)
            __log_into_file(log_in_file, 'a',
                            json.dumps({'HOST': target_to_host(target), 'USERNAME': '', 'PASSWORD': '',
                                        'PORT': "", 'TYPE': 'pma_scan',
                                        'DESCRIPTION': messages(language,"found").format(target, r.status_code, r.reason),
                                        'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id,
                                        'SCAN_CMD': scan_cmd}) + '\n', language)
        return True
    except:
        return False


def test(target, retries, timeout_sec, user_agent, http_method, socks_proxy, verbose_level, trying, total_req, total,
         num, language):
    if verbose_level > 3:
        info(messages(language,"trying_message").format(trying, total_req, num, total, target_to_host(target), "default_port",
                                           'pma_scan'))
    if socks_proxy is not None:
        socks_version = socks.SOCKS5 if socks_proxy.startswith('socks5://') else socks.SOCKS4
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
            socks.set_default_proxy(socks_version, str(socks_proxy.rsplit(':')[0]), int(socks_proxy.rsplit(':')[1]))
            socket.socket = socks.socksocket
            socket.getaddrinfo = getaddrinfo
    n = 0
    while 1:
        try:
            if http_method == "GET":
                r = requests.get(target, timeout=timeout_sec, headers=user_agent)
            elif http_method == "HEAD":
                r = requests.head(target, timeout=timeout_sec, headers=user_agent)
            return 0
        except:
            n += 1
            if n is retries:
                return 1


def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(
            target) != 'HTTP' or target_type(target) != 'SINGLE_IPv6':
        # rand useragent
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
            "msnbot/1.1 (+http://search.msn.com/msnbot.htm)"
        ]
        http_methods = ["GET", "HEAD"]
        user_agent = {'User-agent': random.choice(user_agent_list)}

        # requirements check
        new_extra_requirements = extra_requirements_dict()
        if methods_args is not None:
            for extra_requirement in extra_requirements_dict():
                if extra_requirement in methods_args:
                    new_extra_requirements[extra_requirement] = methods_args[extra_requirement]
        extra_requirements = new_extra_requirements
        if extra_requirements["pma_scan_http_method"][0] not in http_methods:
            warn(messages(language,"dir_scan_get"))
            extra_requirements["pma_scan_http_method"] = ["GET"]
        random_agent_flag = True
        if extra_requirements["pma_scan_random_agent"][0] == "False":
            random_agent_flag = False
        threads = []
        total_req = len(extra_requirements["pma_scan_list"])
        thread_tmp_filename = '{}/tmp/thread_tmp_'.format(load_file_path()) + ''.join(
            random.choice(string.ascii_letters + string.digits) for _ in range(20))
        __log_into_file(thread_tmp_filename, 'w', '1', language)
        trying = 0
        if target_type(target) != "HTTP":
            target = 'http://' + target
        if test(target, retries, timeout_sec, user_agent, extra_requirements["pma_scan_http_method"][0],
                socks_proxy, verbose_level, trying, total_req, total, num, language) is 0:
            keyboard_interrupt_flag = False
            for idir in extra_requirements["pma_scan_list"]:
                if random_agent_flag:
                    user_agent = {'User-agent': random.choice(user_agent_list)}
                t = threading.Thread(target=check,
                                     args=(
                                         target + '/' + idir, user_agent, timeout_sec, log_in_file, language,
                                         time_sleep, thread_tmp_filename, retries,
                                         extra_requirements["pma_scan_http_method"][0], socks_proxy, scan_id, scan_cmd))
                threads.append(t)
                t.start()
                trying += 1
                if verbose_level > 3:
                    info(messages(language,"trying_message").format(trying, total_req, num, total, target_to_host(target),
                                                       "default_port", 'pma_scan'))
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
            warn(messages(language,"open_error").format(target))

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
        if thread_write is 1:
            info(messages(language,"directory_file_404").format(target, "default_port"))
            if verbose_level is not 0:
                __log_into_file(log_in_file, 'a', json.dumps(
                    {'HOST': target_to_host(target), 'USERNAME': '', 'PASSWORD': '', 'PORT': '', 'TYPE': 'pma_scan',
                     'DESCRIPTION': messages(language,"phpmyadmin_dir_404"), 'TIME': now(), 'CATEGORY': "scan",
                     'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}) + '\n', language)
        os.remove(thread_tmp_filename)
    else:
        warn(messages(language,"input_target_error").format('pma_scan', target))
