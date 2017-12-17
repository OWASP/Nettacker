#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket


def getaddrinfo(*args):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (args[0], args[1]))]
