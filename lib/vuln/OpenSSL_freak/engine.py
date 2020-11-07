#!/usr/bin/env python
# -*- coding: utf-8 -*-
import socket
import time
import json
import threading
import string
import random
import subprocess
from core.alert import info
from core.alert import messages
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from core._time import now
from core.log import __log_into_file
from core.alert import warn


def extra_requirements_dict():
    return {
        "freak_vuln_ports": [80, 443]
    }


def freak_vuln(target, port, timeout_sec, log_in_file, language, time_sleep,
               thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    ip_address = socket.gethostbyname(target)
    try:
        result = subprocess.Popen(['timeout', str(time), 'openssl', 's_client',
                                   '-connect', ip_address+":"+str(port),
                                   "-cipher", "EXPORT"],
                                  stderr=subprocess.STDOUT,
                                  stdout=subprocess.PIPE).communicate()[0]
        if "Cipher is EXP".encode('ascii') in result:
            return True
        else:
            return False
    except Exception:
        # some error warning
        return False


def __freak_vuln(target, port, timeout_sec, log_in_file, language, time_sleep,
                 thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    if(freak_vuln(target, port, timeout_sec, log_in_file, language, time_sleep,
                  thread_tmp_filename, socks_proxy, scan_id, scan_cmd)):
        info(messages(language, "target_vulnerable")
             .format(target, port, 'Vulnerable to freak attack'))
        __log_into_file(thread_tmp_filename, 'w', '0', language)
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '',
                           'PORT': port, 'TYPE': 'OpensSSL_freak_vuln',
                           'DESCRIPTION': messages(language, "vulnerable")
                           .format(''), 'TIME': now(),
                           'CATEGORY': "vuln",
                           'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
        __log_into_file(log_in_file, 'a', data, language)
        return True
    else:
        return False


def start(target, users, passwds, ports, timeout_sec, thread_number,
          num, total, log_in_file, time_sleep,
          language, verbose_level, socks_proxy, retries,
          methods_args, scan_id, scan_cmd):  # Main function
    if (
        target_type(target) != 'SINGLE_IPv4'
        or target_type(target) != 'DOMAIN'
        or target_type(target) != 'HTTP'
    ):
        # requirements check
        new_extra_requirements = extra_requirements_dict()
        if methods_args is not None:
            for extra_requirement in extra_requirements_dict():
                if extra_requirement in methods_args:
                    new_extra_requirements[
                        extra_requirement] = methods_args[extra_requirement]
        extra_requirements = new_extra_requirements
        if ports is None:
            ports = extra_requirements["freak_vuln_ports"]
        if target_type(target) == 'HTTP':
            target = target_to_host(target)
        threads = []
        total_req = len(ports)
        thread_tmp_filename = '{}/tmp/thread_tmp_'.format(
            load_file_path()) + ''.join(random.choice(
                string.ascii_letters + string.digits) for _ in range(20))
        trying = 0
        keyboard_interrupt_flag = False
        for port in ports:
            port = int(port)
            t = threading.Thread(target=__freak_vuln,
                                 args=(target, int(port), timeout_sec,
                                       log_in_file, language, time_sleep,
                                       thread_tmp_filename, socks_proxy, 
                                       scan_id, scan_cmd))
            threads.append(t)
            t.start()
            trying += 1
            if verbose_level > 3:
                info(
                    messages(language, "trying_message")
                    .format(trying, total_req, num, total, target, port,
                            'freak_vuln'))
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
    else:
        warn(messages(language, "input_target_error").format(
            'freak_vuln', target))
