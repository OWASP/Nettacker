#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import time
import random
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
    time.sleep(1.0000 * random.choice(range(0,1000)) / 1000)
    if version() is 2:
        sys.stdout.write(color.color('yellow') + '[+] ' + color.color('green') +
                         content.encode('utf8') + color.color('reset') + "\n")
    else:
        sys.stdout.buffer.write(bytes(color.color('yellow') + '[+] ' + color.color('green') +
                                      content + color.color('reset') + "\n", 'utf8'))
    return


def write(content):
    time.sleep(1.0000 * random.choice(range(0, 1000)) / 1000)
    if version() is 2:
        sys.stdout.write(content.encode('utf8'))
    else:
        sys.stdout.buffer.write(bytes(content, 'utf8'))
    return


def warn(content):
    time.sleep(1.0000 * random.choice(range(0, 1000)) / 1000)
    if version() is 2:
        sys.stdout.write(color.color('blue') + '[!] ' + color.color('yellow') +
                         content.encode('utf8') + color.color('reset') + "\n")
    else:
        sys.stdout.buffer.write(bytes(color.color('blue') + '[!] ' + color.color('yellow') +
                                      content + color.color('reset') + "\n", 'utf8'))
    return


def error(content):
    time.sleep(1.0000 * random.choice(range(0, 1000)) / 1000)
    if version() is 2:
        sys.stdout.write(color.color('red') + '[X] ' + color.color('yellow') +
                         content.encode('utf8') + color.color('reset') + "\n")
    else:
        data = color.color('red') + '[X] ' + color.color('yellow') + content + color.color('reset') + "\n"
        sys.stdout.buffer.write(data.encode('utf8'))
    return
