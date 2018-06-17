#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import json
from core import color
from core.compatible import version


def is_not_run_from_api():
    """
    check if framework run from API to prevent any alert

    Returns:
        True if run from API otherwise False
    """
    if '--start-api' in sys.argv or (len(sys.argv) == 4 and 'transforms' in sys.argv[1]):
        return False
    return True


def messages(language, msg_id):
    """
    load a message from message library with specified language

    Args:
        language: language
        msg_id: message id

    Returns:
        the message content in the selected language if message found otherwise return message in English
    """
    # Returning selected langauge
    if language is -1:
        return list(set([langs.rsplit('_')[1].rsplit('.')[0] for langs in
                         os.listdir(os.path.dirname(os.path.abspath(__file__)).replace(
                             '\\', '/') + '/../lib/language/')
                         if langs != 'readme.md' and langs.rsplit('_')[1].rsplit('.')[0] != '']))
    # Importing messages
    try:
        msgs = getattr(__import__('lib.language.messages_{0}'.format(language), fromlist=['all_messages']),
                       'all_messages')()[str(msg_id)]
    except:
        msgs = getattr(__import__('lib.language.messages_en', fromlist=['all_messages']), 'all_messages')()[str(msg_id)]
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


def info(content, log_in_file=None, mode=None, event=None, language=None, thread_tmp_filename=None):
    """
    build the info message, log the message in database if requested, rewrite the thread temporary file

    Args:
        content: content of the message
        log_in_file: log filename name
        mode: write mode, [w, w+, wb, a, ab, ...]
        event: standard event in JSON structure
        language: the language
        thread_tmp_filename: thread temporary filename

    Returns:
        None
    """
    if is_not_run_from_api():  # prevent to stdout if run from API
        if version() is 2:
            sys.stdout.write(color.color('yellow') + '[+] ' + color.color('green') +
                             content.encode('utf8') + color.color('reset') + '\n')
        else:
            sys.stdout.buffer.write(bytes(color.color('yellow') + '[+] ' + color.color('green') +
                                          content + color.color('reset') + '\n', 'utf8'))
    if event:  # if an event is present log it
        from core.log import __log_into_file
        __log_into_file(log_in_file, mode, json.dumps(event), language)
        if thread_tmp_filename:  # if thread temporary filename present, rewrite it
            __log_into_file(thread_tmp_filename, "w", "0", language)
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
            sys.stdout.buffer.write(bytes(content, 'utf8') if isinstance(content, str) else content)
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
            data = color.color(
                'red') + '[X] ' + color.color('yellow') + content + color.color('reset') + '\n'
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
