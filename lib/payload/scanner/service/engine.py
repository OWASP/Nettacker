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
    print(data2)
    name = socket.getservbyport(port)

    if name.upper() in data1 or name.upper() in data2:
        return socket.getservbyport(port)

