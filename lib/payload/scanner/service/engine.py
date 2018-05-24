#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Pradeep Jairamani , github.com/pradeepjairamani
# Service Scanner (Product and Version Detection)

import threading
import socket
import ssl
import time

result_dict = {}

ports_services_and_condition = {
    "HTTP/HTTPS": ["Content-Length:", ["HTTP/0.9", "HTTP/1.0", "HTTP/1.1", "HTTP/2.0"]],
    "FTP" : ["FTP", ["214", "220", "530", "230", "502", "500"]],
    "SSH" : ["SSH"],
    "Telnet" : ["Telnet"],
    "SMTP" : ["SMTP", ["220", "554", "250"]]
}

ports_services_or_condition = {
    "HTTP/HTTPS" : ["400 Bad Request", "HTML"],
    "FTP": [ ["Pure-FTPd", "----------\r\n"], "\r\n220-You are user number", ["orks FTP server", "VxWorks VxWorks"], "530 USER and PASS required", "Server ready.\r\n5", "Invalid command: try being more creative"],
    "SSH": ["-OpenSSH_", "\r\nProtocol mism", "_sshlib GlobalSCAPE\r\n", "\x00\x1aversion info line too long"],
    "Telnet" : ["Welcome to Microsoft Telnet Service", "no decompiling or reverse-engineering shall be allowed", "is not a secure protocol", "recommended to use Stelnet", "Login authentication"],
    "SMTP" : ["Server ready", "SMTP synchronization error", "220-Greetings", "ESMTP Arnet Email Security", "SMTP 2.0", "Fidelix Fx2020"]
}

def recv_all(s):
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


def discover(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((host, port))
    except Exception:
        return None
    try:
        sock = ssl.wrap_socket(sock)
    except Exception:
        #No SSL Support for Service
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
        except Exception:
            return None
    data1 = recv_all(sock)
    sock.send(b"ABC\x00\r\n"*10)
    final_data = recv_all(sock) + data1
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
            result_dict[port] = service
            return
        c += 1

    for service in ports_services_or_condition:
        FLAG = False
        c = 0
        for signature in ports_services_and_condition[service]:
            if isinstance(signature, list):
                OFLAG = True
                for s in ports_services_and_condition[service][c]:
                    if s not in final_data:
                        OFLAG = False
                if OFLAG:
                    FLAG = True
            else:
                if signature in final_data:
                    FLAG = True
        if FLAG:
            result_dict[port] = service; print("or Break")
            return
        c += 1


def discovery(target, port=""):
    if port != "":
        discover(target, port)
        return result_dict
    else:
        threads = []
        ports = [80, 443, 25, 587, 23, 22, 21, 990]
        thread_number = len(ports)
        for port in ports:
            t = threading.Thread(target=discover, args=(target, int(port)))
            threads.append(t)
            t.start()
            while 1:
                try:
                    if threading.activeCount() >= thread_number:
                        time.sleep(1)
                    else:
                        break
                except KeyboardInterrupt:
                    break
        return result_dict
