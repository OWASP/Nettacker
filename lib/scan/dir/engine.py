#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import socks
import time
import json
import threading
import string
import random
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
from core._die import __die_failure


def extra_requirements_dict():
    return {
        "dir_scan_ports": ["80"],
        "dir_scan_http_method": ["GET"],
        "dir_scan_random_agent": ["True"],
        "dir_scan_list": ["~adm", "~admin", "~administrator", "~amanda", "~apache", "~bin", "~ftp", "~guest", "~http",
                          "~httpd", "~log", "~logs", "~lp", "~mail", "~nobody", "~operator", "~root", "~sys", "~sysadm",
                          "~sysadmin", "~test", "~tmp", "~user", "~webmaster", "~www", "wp-admin", "wp-login.php",
                          "administrator", "~backup", "backup.sql", "database.sql", "backup.zip", "backup.tar.gz",
                          "backup", "backup-db", "mysql.sql", "phpmyadmin", "admin", "administrator", "server-status",
                          "server-info", "info.php", "php.php", "info.php", "phpinfo.php", "test.php", ".git",
                          ".htaccess", ".htaccess.old", ".htaccess.save", ".htaccess.txt", ".php-ini", "php-ini",
                          "FCKeditor", "FCK", "editor", "Desktop.ini", "INSTALL", "install", "install.php", "update",
                          "upgrade", "upgrade.php", "update.php", "LICENSE", "LICENSE.txt", "Server.php", "WS_FTP.LOG",
                          "WS_FTP.ini", "WS_FTP.log", "Web.config", "Webalizer", "webalizer", "config.php",
                          "config.php.new", "config.php~", "controlpanel", "cpanel", "favicon.ico", "old", "php-error",
                          "php.ini~", "php.ini", "php.log", "robots.txt", "security", "webdav", "1"]
    }


def check(target, user_agent, timeout_sec, log_in_file, language, time_sleep, thread_tmp_filename, retries,
          http_method, socks_proxy, scan_id, scan_cmd):
    status_codes = [200, 401, 403]
    directory_listing_msgs = ["<title>Index of /", "<a href=\"\\?C=N;O=D\">Name</a>", "Directory Listing for",
                              "Parent Directory</a>", "Last modified</a>", "<TITLE>Folder Listing.",
                              "- Browsing directory "]
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
                    r = requests.get(target, timeout=timeout_sec, headers=user_agent, verify=True)
                elif http_method == "HEAD":
                    r = requests.head(target, timeout=timeout_sec, headers=user_agent, verify=True)
                content = r.content
                break
            except:
                n += 1
                if n is retries:
                    warn(messages(language, 106).format(target))
                    return 1
        if version() is 3:
            content = content.decode('utf8')
        if r.status_code in status_codes:
            info(messages(language, 38).format(target, r.status_code, r.reason))
            __log_into_file(thread_tmp_filename, 'w', '0')
            data = json.dumps({'HOST': target_to_host(target), 'USERNAME': '', 'PASSWORD': '', 
                'PORT': int(target.rsplit(':')[2].rsplit('/')[0]), 'TYPE': 'dir_scan', 
                'DESCRIPTION': messages(language, 38).format(target, r.status_code, r.reason), 
                'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
            __log_into_file(log_in_file, 'a', data)
            if r.status_code is 200:
                for dlmsg in directory_listing_msgs:
                    if dlmsg in content:
                        info(messages(language, 104).format(target))
                        data = json.dumps({'HOST': target_to_host(target), 'USERNAME': '', 'PASSWORD': '', 
                            'PORT': int(target.rsplit(':')[1].rsplit('/')[0]), 'TYPE': 'dir_scan', 
                            'DESCRIPTION': messages(language, 104).format(target), 'TIME': now(), 
                            'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
                        __log_into_file(log_in_file, 'a', data)
                        break
        return True
    except:
        return False


def test(target, retries, timeout_sec, user_agent, http_method, socks_proxy, verbose_level, trying, total_req, total,
         num, port, language):
    if verbose_level > 3:
        info(messages(language, 72).format(trying, total_req, num, total, target_to_host(target), port,
                                           'dir_scan'))
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
                r = requests.get(target, timeout=timeout_sec, headers=user_agent, verify=True)
            elif http_method == "HEAD":
                r = requests.head(target, timeout=timeout_sec, headers=user_agent, verify=True)
            return 0
        except:
            n += 1
            if n is retries:
                return 1


def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, ping_flag, methods_args, scan_id, scan_cmd):  # Main function
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(target) != 'HTTP' or target_type(target) != 'SINGLE_IPv6':
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
        if extra_requirements["dir_scan_http_method"][0] not in http_methods:
            warn(messages(language, 110))
            extra_requirements["dir_scan_http_method"] = ["GET"]
        if ports is None:
            ports = extra_requirements["dir_scan_ports"]
        random_agent_flag = True
        if extra_requirements["dir_scan_random_agent"][0] == "False":
            random_agent_flag = False
        if ping_flag:
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
                    socks.set_default_proxy(socks_version, str(socks_proxy.rsplit(':')[0]),
                                            int(socks_proxy.rsplit(':')[1]))
                    socket.socket = socks.socksocket
                    socket.getaddrinfo = getaddrinfo
            warn(messages(language, 100).format(target, 'heartbleed_vuln'))
            if do_one_ping(target, timeout_sec, 8) is None:
                return None
        threads = []
        max = thread_number
        total_req = len(extra_requirements["dir_scan_list"]) * len(ports)
        filepath = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
        thread_tmp_filename = '{}/tmp/thread_tmp_'.format(load_file_path()) + ''.join(
            random.choice(string.ascii_letters + string.digits) for _ in range(20))
        __log_into_file(thread_tmp_filename, 'w', '1')
        trying = 0
        for port in ports:
            port = int(port)
            if target_type(target) == 'SINGLE_IPv4' or target_type(target) == 'DOMAIN':
                url = 'http://{0}:{1}/'.format(target, str(port))
            else:
                if target.count(':') > 1:
                    __die_failure(messages(language, 105))
                http = target.rsplit('://')[0]
                host = target_to_host(target)
                path = "/".join(target.replace('http://', '').replace('https://', '').rsplit('/')[1:])
                url = http + '://' + host + ':' + str(port) + '/' + path
            if test(url, retries, timeout_sec, user_agent, extra_requirements["dir_scan_http_method"][0],
                    socks_proxy, verbose_level, trying, total_req, total, num, port, language) is 0:
                for idir in extra_requirements["dir_scan_list"]:
                    # check target type
                    if target_type(target) == 'SINGLE_IPv4' or target_type(target) == 'DOMAIN':
                        url = 'http://{0}:{1}/{2}'.format(target, str(port), idir)
                    else:
                        http = target.rsplit('://')[0]
                        host = target_to_host(target)
                        path = "/".join(target.replace('http://', '').replace('https://', '').rsplit('/')[1:])
                        url = http + '://' + host + ':' + str(port) + '/' + path + '/' + idir

                    if random_agent_flag:
                        user_agent = {'User-agent': random.choice(user_agent_list)}
                    t = threading.Thread(target=check,
                                         args=(url, user_agent, timeout_sec, log_in_file, language, time_sleep,
                                               thread_tmp_filename, retries,
                                               extra_requirements["dir_scan_http_method"][0], socks_proxy, scan_id,
                                               scan_cmd))
                    threads.append(t)
                    t.start()
                    trying += 1
                    if verbose_level > 3:
                        info(messages(language, 72).format(trying, total_req, num, total, target_to_host(target), port,
                                                           'dir_scan'))
                    while 1:
                        try:
                            if threading.activeCount() >= max:
                                time.sleep(0.01)
                            else:
                                break
                        except KeyboardInterrupt:
                            break
                            break
            else:
                warn(messages(language, 109).format(url))

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
            info(messages(language, 108).format(target, ",".join(map(str, ports))))
            if verbose_level is not 0:
                data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': '', 'TYPE': 'dir_scan', 
                    'DESCRIPTION': messages(language, 94), 'TIME': now(), 'CATEGORY': "scan", 
                    'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
                __log_into_file(log_in_file, 'a', data)
        os.remove(thread_tmp_filename)
    else:
        warn(messages(language, 69).format('dir_scan', target))
