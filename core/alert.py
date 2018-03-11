#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
from core import color
from core.compatible import version


def is_not_run_from_api():
    """
    check if framework run from API to prevent any alert

    Returns:
        True if run from API otherwise False
    """
    if '--start-api' in sys.argv:
        return False
    return True


def messages(language, msg_id):
    """
    load a message in the lib/language/*.py

    Args:
        language: language
        msg_id: message id

    Returns:
        the message content in the selected language if message found otherwise return message in English
    """
    # Returning selected langauge
    if language is -1:
        return list(set([langs.rsplit('_')[1].rsplit('.')[0] for langs in
                         os.listdir(os.path.dirname(os.path.abspath(__file__)).replace('\\', '/') + '/../lib/language/')
                         if langs != 'readme.md' and langs.rsplit('_')[1].rsplit('.')[0] != '']))
    # Importing messages
    try:
        msgs = getattr(__import__('lib.language.messages_{0}'.format(language), fromlist=['all_messages']),
                               'all_messages')()[str(msg_id)]
    except:
        msgs = getattr(__import__('lib.language.messages_en'.format(language), fromlist=['all_messages']),
                               'all_messages')()[str(msg_id)]
    if version() is 2:
        return msgs.decode('utf8')
    return msgs


def __input_msg(content):
    """
    build the input message to get input from users

    Args:
        content: content of the message

    Returns:
        the message in input structure
    """
    if version() is 2:
        return color.color('yellow') + '[+] ' + color.color('green') \
               + content.encode('utf8') + color.color('reset')
    else:
        return bytes(color.color('yellow') + '[+] ' + color.color('green') +
                     content + color.color('reset'), 'utf8')


def info(content):
    """
    build the info message

    Args:
        content: content of the message

    Returns:
        the message in info structure - None
    """
    if is_not_run_from_api():
        if version() is 2:
            sys.stdout.write(color.color('yellow') + '[+] ' + color.color('green') +
                             content.encode('utf8') + color.color('reset') + '\n')
        else:
            sys.stdout.buffer.write(bytes(color.color('yellow') + '[+] ' + color.color('green') +
                                          content + color.color('reset') + '\n', 'utf8'))
    return


def write(content):
    """
    simple print a message

    Args:
        content: content of the message

    Returns:
        None
    """
    if is_not_run_from_api():
        if version() is 2:
            sys.stdout.write(content.encode('utf8'))
        else:
            sys.stdout.buffer.write(bytes(content, 'utf8'))
    return


def warn(content):
    """
    build the warn message

    Args:
        content: content of the message

    Returns:
        the message in warn structure - None
    """
    if is_not_run_from_api():
        if version() is 2:
            sys.stdout.write(color.color('blue') + '[!] ' + color.color('yellow') +
                             content.encode('utf8') + color.color('reset') + '\n')
        else:
            sys.stdout.buffer.write(bytes(color.color('blue') + '[!] ' + color.color('yellow') +
                                          content + color.color('reset') + '\n', 'utf8'))
    return


def error(content):
    """
    build the error message

    Args:
        content: content of the message

    Returns:
        the message in error structure - None
    """
    if is_not_run_from_api():
        if version() is 2:
            sys.stdout.write(color.color('red') + '[X] ' + color.color('yellow') +
                             content.encode('utf8') + color.color('reset') + '\n')
        else:
            data = color.color('red') + '[X] ' + color.color('yellow') + content + color.color('reset') + '\n'
            sys.stdout.buffer.write(data.encode('utf8'))
    return


def write_to_api_console(content):
    """
    simple print a message in API mode

    Args:
        content: content of the message

    Returns:
        None
    """
    if version() is 2:
        sys.stdout.write(content.encode('utf8'))
    else:
        sys.stdout.buffer.write(bytes(content, 'utf8'))
    return
