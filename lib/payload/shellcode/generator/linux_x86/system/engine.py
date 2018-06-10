#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import inspect
from lib.payload.shellcode.stack import engine as stack


def join_payload(command):
    return open(os.path.dirname(inspect.getfile(start)) + "/system.asm").read().format(*command)


def start(data):
    command = data.replace('[space]', ' ')
    if int(len(command)) < 5:
        command = str(
            command) + '[space]&&[space]echo[space]1[space]>[space]/dev/null'  # bypass a bug in here, fix later
    return join_payload([stack.generate(command.replace('[space]', ' '), '%ecx', 'string')])
