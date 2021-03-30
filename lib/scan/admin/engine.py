#!/usr/bin/env python
# -*- coding: utf-8 -*-

import string
import random
from core.alert import warn, messages
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from core._time import now
from core.log import __log_into_file
from lib.http_fuzzer.engine import __repeater
from core._die import __die_failure
from lib.payload.wordlists import useragents
from core.compatible import version
from lib.scan.admin import admin_scan
import six

def extra_requirements_dict():
    return {
        "admin_scan_http_method": ["GET"],
        "admin_scan_random_agent": ["True"],
        "admin_scan_list": admin_scan.admin_scan(),
    }


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

        http_methods = ["GET", "HEAD"]
        new_extra_requirements = extra_requirements_dict()
        if methods_args is not None:
            for extra_requirement in extra_requirements_dict():
                if extra_requirement in methods_args:
                    new_extra_requirements[extra_requirement] = methods_args[
                        extra_requirement
                    ]
        extra_requirements = new_extra_requirements
        if extra_requirements["admin_scan_http_method"][0] not in http_methods:
            warn(messages(language, "admin_scan_get"))
            extra_requirements["admin_scan_http_method"] = ["GET"]
        thread_tmp_filename = "{}/tmp/thread_tmp_".format(
            load_file_path()
        ) + "".join(
            random.choice(string.ascii_letters + string.digits)
            for _ in range(20)
        )
        __log_into_file(thread_tmp_filename, "w", "1", language)
        default_ports = [80, 443]
        request = """{0} __target_locat_here__{{0}} HTTP/1.1\
            \nUser-Agent: {1}\n\n""".format(
            extra_requirements["admin_scan_http_method"][0],
            random.choice(useragents.useragents())
            if extra_requirements["admin_scan_random_agent"][0].lower()
            == "true"
            else "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.5)\
                Gecko/20060719 Firefox/1.5.0.5",
        )
        status_codes = [200, 401, 403]
        condition = "response.status_code in {0}".format(status_codes)
        message = messages(language, "found")
        sample_message = (
            '"'
            + message
            + '"'
            + """.format(response.url,\
                        response.status_code,\
                        response.reason)"""
        )
        sample_event = {
            "HOST": target_to_host(target),
            "USERNAME": "",
            "PASSWORD": "",
            "PORT": "PORT",
            "TYPE": "admin_scan",
            "DESCRIPTION": sample_message,
            "TIME": now(),
            "CATEGORY": "scan",
            "SCAN_ID": scan_id,
            "SCAN_CMD": scan_cmd,
        }
        counter_message = messages(language, "admin_dir_404")
        __repeater(
            request,
            [extra_requirements["admin_scan_list"]],
            timeout_sec,
            thread_number,
            log_in_file,
            time_sleep,
            language,
            verbose_level,
            socks_proxy,
            retries,
            scan_id,
            scan_cmd,
            condition,
            thread_tmp_filename,
            sample_event,
            sample_message,
            target,
            ports,
            default_ports,
            counter_message,
        )

    else:
        warn(
            messages(language, "input_target_error").format(
                "admin_scan", target
            )
        )
