#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from core import color
from core.languages import all_messages
from core.compatible import version


def messages(language, msg_id):
    # Importing messages
    msgs = all_messages()

    # Returning selected langauge
    if language is -1:
        return msgs["0"]

    if version() is 2:
        # Returning message
        try:
            return msgs[str(msg_id)][language].decode('utf8')
        except:
            return msgs[str(msg_id)]['en'].decode('utf8')
    try:
        return msgs[str(msg_id)][language]
    except:
        return msgs[str(msg_id)]['en']


def info(content):
    if version() is 2:
        sys.stdout.write(color.color('yellow') + '[+] ' + color.color('green') +
                         content.encode('utf8') + color.color('reset') + "\n")
    else:
        sys.stdout.buffer.write(bytes(color.color('yellow') + '[+] ' + color.color('green') +
                                      content + color.color('reset') + "\n", 'utf8'))
    return


def write(content):
    if version() is 2:
        sys.stdout.write(content.encode('utf8'))
    else:
        sys.stdout.buffer.write(bytes(content, 'utf8'))
    return


def warn(content):
    if '\n' in content:
        num_newline = len(content) - len(content.rstrip("\n"))
        if version() is 2:
            sys.stdout.write(color.color('blue') + '[!] ' + color.color('yellow') +
                             content[:-num_newline].encode('utf8') + color.color('reset') + "\n" * num_newline)
        else:
            sys.stdout.buffer.write(bytes(color.color('blue') + '[!] ' + color.color('yellow') +
                                          content[:-num_newline] + color.color('reset') + "\n" * num_newline), 'utf8')
    else:
        if version() is 2:
            sys.stdout.write(color.color('blue') + '[!] ' + color.color('yellow') +
                             content.encode('utf8') + color.color('reset') + "\n")
        else:
            sys.stdout.buffer.write(bytes(color.color('blue') + '[!] ' + color.color('yellow') +
                                          content + color.color('reset') + "\n"), 'utf8')
    return


def error(content):
    if '\n' in content:
        num_newline = len(content) - len(content.rstrip("\n"))
        if version() is 2:
            sys.stdout.write(color.color('red') + '[X] ' + color.color('yellow') +
                             content[:-num_newline].encode('utf8') + color.color('reset') + "\n" * num_newline)
        else:
            sys.stdout.buffer.write(bytes(color.color('red') + '[X] ' + color.color('yellow') +
                                          content[:-num_newline] + color.color('reset') + "\n" * num_newline), 'utf8')
    else:
        if version() is 2:
            sys.stdout.write(color.color('red') + '[X] ' + color.color('yellow') +
                             content.encode('utf8') + color.color('reset') + "\n")
        else:
            data = color.color('red') + '[X] ' + color.color('yellow') + content + color.color('reset') + "\n"
            sys.stdout.buffer.write(data.encode('utf8'))
    return
