#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Pradeep Jairamani , github.com/pradeepjairamani

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
        "cms_detection_ports": [80,443]
    }


def conn(targ, port, timeout_sec, socks_proxy):
    try:
        if socks_proxy is not None:
            socks_version = socks.SOCKS5 if socks_proxy.startswith(
                'socks5://') else socks.SOCKS4
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
                socket.getaddrinfo = getaddrinfo()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sys.stdout.flush()
        s.settimeout(timeout_sec)
        s.connect((targ, port))
        return s
    except Exception as e:
        return None


def cms_detection(target, port, timeout_sec, log_in_file, language, time_sleep,
                   thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    try:
        try:
            s = conn(target, port, timeout_sec, socks_proxy)
        except Exception as e:
            return False
        if not s:
            return False
        else:
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
            "http://help.yahoo.com/help/us/shop/merchant/)"]
            global cms_name
            if target_type(target) != "HTTP" and port == 443:
                target = 'https://' + target
            if target_type(target) != "HTTP" and port == 80:
                target = 'http://' + target
            req_url = target + "/N0WH3R3.php"
            req_joomla_url = target + "/configuration.php"           
            req_wordpress_url = target + "/wp-config.php"
            req_drupal_url = target + "/sites/default/settings.php"
            try:
               user_agent = {'User-agent': random.choice(user_agent_list)}
               req = requests.get(req_url, timeout=10, headers=user_agent)
               code_for_404 = req.text
               user_agent = {'User-agent': random.choice(user_agent_list)}
               req_wordpress = requests.get(req_wordpress_url, timeout=10, headers=user_agent)
               user_agent = {'User-agent': random.choice(user_agent_list)}
               req_joomla = requests.get(req_joomla_url, timeout=10, headers=user_agent)
               user_agent = {'User-agent': random.choice(user_agent_list)}
               req_drupal = requests.get(req_drupal_url, timeout=10, headers=user_agent)
            except requests.exceptions.RequestException as e: 
               return False
            if req_wordpress.text != code_for_404 or req_wordpress.status_code == 403:
                cms_name = "Wordpress"
                return True
            elif req_drupal.status_code != code_for_404 or req_drupal.status_code == 403:
                cms_name = "Drupal"
                return True
            elif req_joomla.status_code != code_for_404 or req_joomla.status_code == 403:
                cms_name = "Joomla"
                return True
            else:
                return False
    except Exception as e:
        #print(e)
        return False


def __cms_detection(target, port, timeout_sec, log_in_file, language, time_sleep,
                     thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    if cms_detection(target, port, timeout_sec, log_in_file, language, time_sleep,
                      thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
        info(messages(language, "found").format(target, "CMS Name", cms_name))
        __log_into_file(thread_tmp_filename, 'w', '0', language)
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'cms_detection_scan',
                           'DESCRIPTION': messages(language, "found").format(target, "CMS Name", cms_name), 'TIME': now(),
                           'CATEGORY': "scan",
                           'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
        __log_into_file(log_in_file, 'a', data, language)
        return True
    else:
        return False


def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(target) != 'HTTP':
        # requirements check
        new_extra_requirements = extra_requirements_dict()
        if methods_args is not None:
            for extra_requirement in extra_requirements_dict():
                if extra_requirement in methods_args:
                    new_extra_requirements[extra_requirement] = methods_args[extra_requirement]
        extra_requirements = new_extra_requirements
        if ports is None:
            ports = extra_requirements["cms_detection_ports"]
        if target_type(target) == 'HTTP':
            target = target_to_host(target)
        threads = []
        total_req = len(ports)
        thread_tmp_filename = '{}/tmp/thread_tmp_'.format(load_file_path()) + ''.join(
            random.choice(string.ascii_letters + string.digits) for _ in range(20))
        __log_into_file(thread_tmp_filename, 'w', '1', language)
        trying = 0
        keyboard_interrupt_flag = False
        for port in ports:
            port = int(port)
            t = threading.Thread(target=__cms_detection,
                                 args=(target, int(port), timeout_sec, log_in_file, language, time_sleep,
                                       thread_tmp_filename, socks_proxy, scan_id, scan_cmd))
            threads.append(t)
            t.start()
            trying += 1
            if verbose_level > 3:
                info(
                    messages(language, "trying_message").format(trying, total_req, num, total, target, port, 'cms_detection_scan'))
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
        kill_time = int(
            timeout_sec / 0.1) if int(timeout_sec / 0.1) is not 0 else 1
        while 1:
            time.sleep(0.1)
            kill_switch += 1
            try:
                if threading.activeCount() is 1:
                    break
            except KeyboardInterrupt:
                break
        thread_write = int(open(thread_tmp_filename).read().rsplit()[0])
        if thread_write is 1 and verbose_level is not 0:
            info(messages(language, "not_found"))
            data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': '', 'TYPE': 'cms_detection_scan',
                               'DESCRIPTION': messages(language, "not_found"), 'TIME': now(),
                               'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
            __log_into_file(log_in_file, 'a', data, language)
        os.remove(thread_tmp_filename)

    else:
        warn(messages(language, "input_target_error").format(
            'cms_detection_scan', target))
