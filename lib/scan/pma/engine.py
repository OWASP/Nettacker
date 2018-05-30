#!/usr/bin/env python
# -*- coding: utf-8 -*-

import string
import random

from core.alert import *
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from core._time import now
from core.log import __log_into_file
from lib.http_fuzzer.engine import __repeater
from lib.http_fuzzer.engine import user_agents_list


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
        http_methods = ["GET", "HEAD"]

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
        thread_tmp_filename = '{}/tmp/thread_tmp_'.format(load_file_path()) + ''.join(
            random.choice(string.ascii_letters + string.digits) for _ in range(20))
        __log_into_file(thread_tmp_filename, 'w', '1', language)
        default_ports = [80, 443]
        request = """{0} __target_locat_here__{{0}} HTTP/1.1\nUser-Agent: {1}\n\n""".format(
            extra_requirements["pma_scan_http_method"][0], random.choice(user_agents_list())
            if extra_requirements["pma_scan_random_agent"][0].lower() == "true" else
            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.5) Gecko/20060719 Firefox/1.5.0.5")
        status_codes = [200, 401, 403]
        condition = "response.status_code in {0}".format(status_codes)
        message = messages(language, 'found')
        sample_message = "\"" + message + "\"" + """.format(response.url, response.status_code, response.reason)"""
        sample_event = {
            'HOST': target_to_host(target),
            'USERNAME': '',
            'PASSWORD': '',
            'PORT': 'PORT',
            'TYPE': 'pma_scan',
            'DESCRIPTION': sample_message,
            'TIME': now(),
            'CATEGORY': "scan",
            'SCAN_ID': scan_id,
            'SCAN_CMD': scan_cmd
        }
        counter_message = messages(language, "phpmyadmin_dir_404")
        __repeater(request, [extra_requirements["pma_scan_list"]], timeout_sec, thread_number, log_in_file, time_sleep,
                   language, verbose_level, socks_proxy, retries, scan_id, scan_cmd, condition, thread_tmp_filename,
                   sample_event, sample_message, target, ports, default_ports, counter_message)
    else:
        warn(messages(language, "input_target_error").format('pma_scan', target))
