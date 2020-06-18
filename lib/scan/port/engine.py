#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import socks
import time
import json
import threading
import string
import random
import os
import logging
from scapy.volatile import RandShort
from core.alert import *
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.log import __log_into_file
from core.compatible import is_windows
from lib.payload.scanner.service.engine import discover_by_port
from lib.scan.port import ports
from scapy.config import conf
from scapy.layers.inet import IP, TCP, ICMP
from scapy.sendrecv import sr1
from scapy import base_classes, plist, utils, data

logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)


def extra_requirements_dict():
    return {  # 1000 common ports used by nmap scanner
        "port_scan_stealth": ["False"],
        "udp_scan": ["False"],
        "port_scan_ports": ports.ports()
    }


if "--method-args" in sys.argv and "port_scan_stealth" in " ".join(sys.argv).lower():

    if is_windows():  # fix later
        from scapy.base_classes import Gen, SetGen
        import scapy.plist as plist
        from scapy.utils import PcapReader
        from scapy.data import MTU, ETH_P_ARP
        import re
        import sys
        import itertools
    WINDOWS = True
    conf.verb = 0
    conf.nofilter = 1


def check_closed(ip):
    for i in range(1, 10):
        s = sr1(IP(dst=ip) / TCP(dport=i), timeout=2, verbose=0)
        if s != 'SA' and s is not None:
            return i
    return 0


def filter_port(ip, port):
    closed_port = check_closed(ip)
    s = sr1(IP(dst=str(ip)) / TCP(dport=port, flags='S'), timeout=2, verbose=0)
    try:
        if s != 'SA':
            try:
                if s[0][1].seq == 0:
                    pass
            except:
                s = sr1(IP(dst=ip) / TCP(dport=closed_port, flags='S'), timeout=2, verbose=0)
                if s == None:
                    return None
                else:
                    return True
    except:
        pass


def stealth(host, port, timeout_sec, log_in_file, language, time_sleep, thread_tmp_filename, socks_proxy, scan_id,
            scan_cmd, stealth_flag):
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
                socks.set_default_proxy(socks_version, str(
                    socks_proxy.rsplit(':')[0]), int(socks_proxy.rsplit(':')[1]))
                socket.socket = socks.socksocket
        src_port = RandShort()

        stealth_scan_resp = sr1(
            IP(dst=host) / TCP(sport=src_port, dport=port, flags="S"), timeout=int(timeout_sec))
        if (str(type(stealth_scan_resp)) == "<type 'NoneType'>"):
            # "Filtered"
            pass
        elif (stealth_scan_resp.haslayer(TCP)):
            if (stealth_scan_resp.getlayer(TCP).flags == 0x12):
                # send_rst = sr(IP(dst=host) / TCP(sport=src_port, dport=port, flags="R"), timeout=timeout_sec)
                try:
                    service_name = "/" + discover_by_port(host, port, timeout_sec, b"ABC\x00\r\n" * 10, socks_proxy,
                                                          external_run=True)
                except Exception as _:
                    service_name = None
                if not service_name or service_name == "/UNKNOWN":
                    try:
                        service_name = "/" + socket.getservbyport(port)
                    except Exception:
                        service_name = ""
                data = json.dumps(
                    {'HOST': host, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'port_scan',
                     'DESCRIPTION': messages(language, "port/type").format(str(port) + service_name, "STEALTH"),
                     'TIME': now(),
                     'CATEGORY': "scan", 'SCAN_ID': scan_id,
                     'SCAN_CMD': scan_cmd}) + '\n'
                __log_into_file(log_in_file, 'a', data, language)
                __log_into_file(thread_tmp_filename, 'w', '0', language)
            elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
                # "Closed"
                pass
        elif (stealth_scan_resp.haslayer(ICMP)):
            if (int(stealth_scan_resp.getlayer(ICMP).type) == 3
                    and int(stealth_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                pass
        else:
            # "CHECK"
            pass
        return True
    except:
        return False


def __udp(host, port, timeout_sec, log_in_file, language, time_sleep, thread_tmp_filename, socks_proxy, scan_id,
          scan_cmd, stealth_flag):
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
                socks.set_default_proxy(socks_version, str(
                    socks_proxy.rsplit(':')[0]), int(socks_proxy.rsplit(':')[1]))
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo
        data = "\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
        if target_type(host) == "SINGLE_IPv6":
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, 0)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if timeout_sec is not None:
            s.settimeout(timeout_sec)
        if target_type(host) == "SINGLE_IPv6":
            s.sendto((host, port, 0, 0))
        else:
            s.sendto(data, (host, port))
        try:
            s.recvfrom(4096)
        except:
            return False
        try:
            service_name = "/" + socket.getservbyport(port)
        except Exception:
            service_name = ""
        info(messages(language, "port_found").format(host, str(port) + service_name, "UDP"), log_in_file,
             "a", {'HOST': host, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'port_scan',
                   'DESCRIPTION': messages(language, "port/type").format(str(port) + service_name, "UDP"),
                   'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}, language,
             thread_tmp_filename)
        s.close()
        return True
    except socket.timeout:
        try:
            service_name = "/" + discover_by_port(host, port, timeout_sec, b"ABC\x00\r\n" * 10, socks_proxy,
                                                  external_run=True)
        except Exception as _:
            service_name = None
        if not service_name or service_name == "/UNKNOWN":
            try:
                service_name = "/" + socket.getservbyport(port)
            except Exception:
                service_name = ""
        try:
            if filter_port(host, port):
                info(messages(language, "port_found").format(host, str(port) + service_name, "TCP_CONNECT"))
                data = json.dumps({'HOST': host, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'port_scan',
                                   'DESCRIPTION': messages(language, "port/type").format(str(port) + service_name,
                                                                                         "TCP_CONNECT"),
                                   'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}) + '\n'
                __log_into_file(log_in_file, 'a', data, language)
                __log_into_file(thread_tmp_filename, 'w', '0', language)
        except:
            pass
    except:
        return False


def connect(host, port, timeout_sec, log_in_file, language, time_sleep, thread_tmp_filename, socks_proxy, scan_id,
            scan_cmd, stealth_flag):
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
                socks.set_default_proxy(socks_version, str(
                    socks_proxy.rsplit(':')[0]), int(socks_proxy.rsplit(':')[1]))
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo
        if target_type(host) == "SINGLE_IPv6":
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if timeout_sec is not None:
            s.settimeout(timeout_sec)
        if target_type(host) == "SINGLE_IPv6":
            s.connect((host, port, 0, 0))
        else:
            s.connect((host, port))
        try:
            service_name = "/" + discover_by_port(host, port, timeout_sec, b"ABC\x00\r\n" * 10, socks_proxy,
                                                  external_run=True)
        except Exception as _:
            service_name = None
        if not service_name or service_name == "/UNKNOWN":
            try:
                service_name = "/" + socket.getservbyport(port)
            except Exception:
                service_name = ""
        info(messages(language, "port_found").format(host, str(port) + service_name, "TCP_CONNECT"), log_in_file,
             "a", {'HOST': host, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'port_scan',
                   'DESCRIPTION': messages(language, "port/type").format(str(port) + service_name, "TCP_CONNECT"),
                   'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}, language,
             thread_tmp_filename)
        s.close()
        return True
    except socket.timeout:
        try:
            service_name = "/" + discover_by_port(host, port, timeout_sec, b"ABC\x00\r\n" * 10, socks_proxy,
                                                  external_run=True)
        except Exception as _:
            service_name = None
        if not service_name or service_name == "/UNKNOWN":
            try:
                service_name = "/" + socket.getservbyport(port)
            except Exception:
                service_name = ""
        try:
            if filter_port(host, port):
                info(messages(language, "port_found").format(host, str(port) + service_name, "TCP_CONNECT"))
                data = json.dumps({'HOST': host, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'port_scan',
                                   'DESCRIPTION': messages(language, "port/type").format(str(port) + service_name,
                                                                                         "TCP_CONNECT"),
                                   'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}) + '\n'
                __log_into_file(log_in_file, 'a', data, language)
                __log_into_file(thread_tmp_filename, 'w', '0', language)
        except:
            pass
    except:
        return False


def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(
            target) != 'HTTP' or target_type(target) != 'SINGLE_IPv6':
        # requirements check
        new_extra_requirements = extra_requirements_dict()
        if methods_args is not None:
            for extra_requirement in extra_requirements_dict():
                if extra_requirement in methods_args:
                    new_extra_requirements[
                        extra_requirement] = methods_args[extra_requirement]
        extra_requirements = new_extra_requirements
        if ports is None:
            ports = extra_requirements["port_scan_ports"]
        try:
            if extra_requirements["port_scan_stealth"][0].lower() == "true":
                stealth_flag = True
                udp_flag = False
            elif extra_requirements["udp_scan"][0].lower() == "true":
                stealth_flag = False
                udp_flag = True
            else:
                stealth_flag = False
                udp_flag = False
        except Exception:
            udp_flag = False
            stealth_flag = False

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
            t = threading.Thread(target=stealth if stealth_flag else (__udp if udp_flag else connect),
                                 args=(target, int(port), timeout_sec, log_in_file, language, time_sleep,
                                       thread_tmp_filename, socks_proxy, scan_id, scan_cmd, stealth_flag))
            threads.append(t)
            t.start()
            time.sleep(time_sleep)
            trying += 1
            if verbose_level > 3:
                info(
                    messages(language, "trying_message").format(trying, total_req, num, total, target, port,
                                                                'port_scan'))
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
            timeout_sec / 0.1) * (5 + timeout_sec) * 10 if int(timeout_sec / 0.1) != 0 else 2
        while 1:
            time.sleep(0.1)
            kill_switch += 1
            try:
                if threading.activeCount() == 1 or kill_switch == kill_time:
                    break
            except KeyboardInterrupt:
                break
        thread_write = int(open(thread_tmp_filename).read().rsplit()[0])
        if thread_write == 1 and verbose_level != 0:
            data = json.dumps(
                {'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': '', 'TYPE': 'port_scan',
                 'DESCRIPTION': messages(language, "no_open_ports"), 'TIME': now(), 'CATEGORY': "scan",
                 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}) + "\n"
            __log_into_file(log_in_file, 'a', data, language)
        os.remove(thread_tmp_filename)

    else:
        warn(messages(language, "input_target_error").format('port_scan', target))
