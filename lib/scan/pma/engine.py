#!/usr/bin/env python
# -*- coding: utf-8 -*-

import string
import random
import os
from core.alert import *
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.log import __log_into_file
from lib.http_fuzzer.engine import __repeater


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
                    new_extra_requirements[
                        extra_requirement] = methods_args[extra_requirement]
        extra_requirements = new_extra_requirements
        if extra_requirements["pma_scan_http_method"][0] not in http_methods:
            warn(messages(language, "dir_scan_get"))
            extra_requirements["pma_scan_http_method"] = ["GET"]
        random_agent_flag = True
        if extra_requirements["pma_scan_random_agent"][0] == "False":
            random_agent_flag = False
        total_req = len(extra_requirements["pma_scan_list"])
        thread_tmp_filename = '{}/tmp/thread_tmp_'.format(load_file_path()) + ''.join(
            random.choice(string.ascii_letters + string.digits) for _ in range(20))
        __log_into_file(thread_tmp_filename, 'w', '1', language)
        if target_type(target) != "HTTP":
            target = 'http://' + target

        request = """{0} {1}{{0}} HTTP/1.1
        User-Agent: {2}
        """.format(extra_requirements["pma_scan_http_method"][0], target, user_agent['User-agent'])
        parameters = list()
        parameters.append(extra_requirements["pma_scan_list"])
        status_codes = [200, 401, 403]
        rule_type = "status_code"
        condition = "response.status_code in {0}".format(status_codes)
        output = __repeater(request, parameters, timeout_sec, thread_number, log_in_file, time_sleep, language,
                            verbose_level, socks_proxy, retries, scan_id, scan_cmd, rule_type, condition)
        for x in output:
            if x['result']:
                info(messages(language, "found").format(
                    x['response'].url, x['response'].status_code, x['response'].reason))
                __log_into_file(thread_tmp_filename, 'w', '0', language)
                __log_into_file(log_in_file, 'a',
                                json.dumps({'HOST': target_to_host(target), 'USERNAME': '', 'PASSWORD': '',
                                            'PORT': "", 'TYPE': 'pma_scan',
                                            'DESCRIPTION': messages(language, "found").format(x['response'].url,
                                                                    x['response'].status_code , x['response'].reason),
                                            'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id,
                                            'SCAN_CMD': scan_cmd}) + '\n', language)

        thread_write = int(open(thread_tmp_filename).read().rsplit()[0])
        if thread_write is 1:
            info(messages(language, "directory_file_404").format(
                target, "default_port"))
            if verbose_level is not 0:
                __log_into_file(log_in_file, 'a', json.dumps(
                    {'HOST': target_to_host(target), 'USERNAME': '', 'PASSWORD': '', 'PORT': '', 'TYPE': 'pma_scan',
                     'DESCRIPTION': messages(language, "phpmyadmin_dir_404"), 'TIME': now(), 'CATEGORY': "scan",
                     'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}) + '\n', language)
        os.remove(thread_tmp_filename)
    else:
        warn(messages(language, "input_target_error").format('pma_scan', target))
