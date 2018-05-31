#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Pradeep Jairamani , github.com/pradeepjairamani
# Service Scanner (Product and Version Detection)

import threading
import socket
import socks
import ssl
import time
import binascii
import requests
import json

from core.config_builder import _builder
from core.config_builder import _core_default_config
from core.config import _core_config
from lib.scan.port.engine import extra_requirements_dict as port_scanner_default_ports

result_dict = {}

ports_services_and_condition = {
    "HTTP": ["Content-Length:", ["HTTP/0.9", "HTTP/1.0", "HTTP/1.1", "HTTP/2.0"]],
    "FTP": ["FTP", ["214", "220", "530", "230", "502", "500"]],
    "SSH": ["SSH"],
    "Telnet": ["Telnet"],
    "SMTP": ["SMTP", ["220", "554", "250"]],
    "IMAP": ["IMAP"],
    "MariaDB": ["MariaDB"],
    "MYSQL": ["MySQL"],
}

ports_services_or_condition = {
    "HTTP": ["400 Bad Request", "HTML"],
    "FTP": [["Pure-FTPd", "----------\r\n"], "\r\n220-You are user number", ["orks FTP server", "VxWorks VxWorks"],
            "530 USER and PASS required", "Server ready.\r\n5", "Invalid command: try being more creative"],
    "SSH": ["-OpenSSH_", "\r\nProtocol mism", "_sshlib GlobalSCAPE\r\n", "\x00\x1aversion info line too long"],
    "Telnet": ["Welcome to Microsoft Telnet Service", "no decompiling or reverse-engineering shall be allowed",
               "is not a secure protocol", "recommended to use Stelnet", "Login authentication"],
    "SMTP": ["Server ready", "SMTP synchronization error", "220-Greetings", "ESMTP Arnet Email Security", "SMTP 2.0",
             "Fidelix Fx2020"],
    "IMAP": ["BAD Error in IMAP command received by server", "IMAP4rev1 SASL-IR", "OK [CAPABILITY IMAP4rev1",
             "LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE NAMESPACE AUTH=PLAIN AUTH=LOGIN]",
             "LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE AUTH=PLAIN AUTH=LOGIN AUTH=DIGEST-MD5 AUTH=CRAM-MD5]"],
    "MariaDB": ["is not allowed to connect to this MariaDB server", "5.5.52-MariaDB", "5.5.5-10.0.34-MariaDB"],
    "MYSQL": ["is not allowed to connect to this MySQL server"]
}


def send_service_scan_diagnostics(services):
    """
    Send services to server, this feature helps us to grab more signatures for our detection. you can disable this
    feature by set the "send_diagnostics" to False in core/config.py

    Args:
        services: founded/unknown services

    Returns:
        requests status code, otherwise the error message
    """
    try:
        return requests.post("http://nettacker.z3r0d4y.com/submit_diagnostics.php", data=services).status_code
    except Exception as _:
        return _


def recv_all(s):
    """

    Args:
        s:

    Returns:

    """
    response = ""
    while len(response) < 4196:
        try:
            r = s.recv(1)
            if r != b"":
                response += r.decode()
            else:
                break
        except Exception as _:
            break
    return response


def discover_by_port(host, port, timeout, send_data, socks_proxy):
    """

    Args:
        host:
        port:
        timeout:
        send_data:
        socks_proxy:

    Returns:

    """

    ssl_flag = False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
    except Exception as _:
        return None
    try:
        sock = ssl.wrap_socket(sock)
        ssl_flag = True
    except Exception as _:
        # No SSL Support for Service
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
        except Exception:
            return None
    data1 = recv_all(sock)
    try:
        sock.send(send_data)
    except Exception as _:
        pass
    final_data = recv_all(sock) + data1  # print( "PORT : " + str(port) +final_data)
    for service in ports_services_and_condition:
        FLAG = True
        c = 0
        for signature in ports_services_and_condition[service]:
            if isinstance(signature, list):
                OFLAG = True
                for s in ports_services_and_condition[service][c]:
                    if s in final_data:
                        OFLAG = False
                if OFLAG:
                    FLAG = False
            else:
                if signature not in final_data:
                    FLAG = False
        if FLAG:
            if ssl_flag:
                result_dict[port] = service + "/SSL"
            else:
                result_dict[port] = service
            return
        c += 1

    for service in ports_services_or_condition:
        FLAG = False
        c = 0
        for signature in ports_services_or_condition[service]:
            if isinstance(signature, list):
                OFLAG = True
                for s in ports_services_or_condition[service][c]:
                    if s not in final_data:
                        OFLAG = False
                if OFLAG:
                    FLAG = True
            else:
                if signature in final_data:
                    FLAG = True
        if FLAG:
            if ssl_flag:
                result_dict[port] = service + "/SSL"
            else:
                result_dict[port] = service
            return
        c += 1
    if len(final_data):
        try:
            result_dict[port]
        except Exception as _:
            result_dict[port] = "UNKNOWN"


def discovery(target, ports=None, timeout=3, thread_number=1000, send_data=None, time_sleep=0, socks_proxy=None):
    """

    Args:
        target:
        ports:
        timeout:
        thread_number:
        send_data:
        time_sleep:
        socks_proxy:

    Returns:

    """

    threads = []
    if not send_data:
        send_data = b"ABC\x00\r\n" * 10
    if not ports:
        ports = port_scanner_default_ports()["port_scan_ports"]
    for port in ports:
        t = threading.Thread(target=discover_by_port, args=(target, int(port), int(timeout), send_data, socks_proxy))
        threads.append(t)
        t.start()
        time.sleep(time_sleep)
        while 1:
            try:
                if threading.activeCount() >= thread_number:
                    time.sleep(1)
                else:
                    break
            except KeyboardInterrupt:
                break
    kill_switch = 0
    while 1:
        time.sleep(0.1)
        kill_switch += 1
        try:
            if threading.activeCount() is 1 or int(kill_switch) is int(timeout * 2 * 10):
                break
        except KeyboardInterrupt:
            break
    if _builder(_core_config(), _core_default_config())["send_diagnostics"]:
        diagnostics_data = {}
        diagnostics_data["services"] = json.dumps(result_dict)
        diagnostics_data["timeout"] = timeout
        diagnostics_data["thread_number"] = thread_number
        diagnostics_data["send_data"] = binascii.b2a_base64(send_data)
        diagnostics_data["target"] = target
        send_service_scan_diagnostics(diagnostics_data)
    return result_dict
