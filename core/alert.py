#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import time
import random
from core import color
from core.compatible import version


def messages(language, msg_id):
    # Returning selected langauge
    if language is -1:
        return list(set([langs.rsplit('_')[1].rsplit('.')[0] for langs in
                         os.listdir(os.path.dirname(os.path.abspath(__file__)).replace('\\', '/') + '/../lib/language/')
                         if
                         langs != 'readme.md']))
    all_messages = getattr(__import__('lib.language.messages_{0}'.format(language), fromlist=['all_messages']),
                           'all_messages')
    # Importing messages
    msgs = all_messages()[str(msg_id)]
    if version() is 2:
        try:
            return msgs.decode('utf8') if msgs != '' else \
                getattr(__import__('lib.language.messages_en'.format(language), fromlist=['all_messages']),
                        'all_messages')()[str(msg_id)].decode('utf8')
        except:
            return getattr(__import__('lib.language.messages_en'.format(language), fromlist=['all_messages']),
                           'all_messages')()[str(msg_id)].decode('utf8')
    try:
        return msgs if msgs != '' else \
            getattr(__import__('lib.language.messages_en'.format(language), fromlist=['all_messages']),
                    'all_messages')()[str(msg_id)]
    except:
        return getattr(__import__('lib.language.messages_en'.format(language), fromlist=['all_messages']),
                       'all_messages')()[str(msg_id)]


def info(content):
    time.sleep(1.0000 * random.choice(range(0, 1000)) / 1000)
    if version() is 2:
        sys.stdout.write(color.color('yellow') + '[+] ' + color.color('green') +
                         content.encode('utf8') + color.color('reset') + '\n')
    else:
        sys.stdout.buffer.write(bytes(color.color('yellow') + '[+] ' + color.color('green') +
                                      content + color.color('reset') + '\n', 'utf8'))
    return


def write(content):
    if version() is 2:
        sys.stdout.write(content.encode('utf8'))
    else:
        sys.stdout.buffer.write(bytes(content, 'utf8'))
    return


def warn(content):
    time.sleep(1.0000 * random.choice(range(0, 1000)) / 1000)
    if version() is 2:
        sys.stdout.write(color.color('blue') + '[!] ' + color.color('yellow') +
                         content.encode('utf8') + color.color('reset') + '\n')
    else:
        sys.stdout.buffer.write(bytes(color.color('blue') + '[!] ' + color.color('yellow') +
                                      content + color.color('reset') + '\n', 'utf8'))
    return


def error(content):
    time.sleep(1.0000 * random.choice(range(0, 1000)) / 1000)
    if version() is 2:
        sys.stdout.write(color.color('red') + '[X] ' + color.color('yellow') +
                         content.encode('utf8') + color.color('reset') + '\n')
    else:
        data = color.color('red') + '[X] ' + color.color('yellow') + content + color.color('reset') + '\n'
        sys.stdout.buffer.write(data.encode('utf8'))
    return
