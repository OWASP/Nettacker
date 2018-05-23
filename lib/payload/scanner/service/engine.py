#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Pradeep Jairamani , github.com/pradeepjairamani
# Service Scanner (Product and Version Detection)

import socket
import ssl

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

ports_services = {"Content-Length" : "HTTP/HTTPS", "HTTP" : "HTTP/HTTPS", "FTP" : "FTP", "ftp" : "FTP", "SMTP": "SMTP", "smtp" : "SMTP", "mail" : "SMTP" , "Telnet" : "Telnet", "telnet": "Telnet", "SSH": "SSH", "ssh" : "SSH"}

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
        except:
            return None
    data1 = (recv_all(sock))
    sock.send(b"ABC\x00\r\n"*10)
    data2 = (recv_all(sock))
    #print data1
    #print data2
    name = socket.getservbyport(port)
    for key in ports_services.keys():
        if key in data1 or key in data2:
            return ports_services[key]

