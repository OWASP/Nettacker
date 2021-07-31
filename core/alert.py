#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
from core import color
from core.messages import load_message

message_cache = load_message().messages


def is_not_run_from_api():
    """
    check if framework run from API to prevent any alert

    Returns:
        True if run from API otherwise False
    """
    if "--start-api" in sys.argv or (
            len(sys.argv) == 4 and "transforms" in sys.argv[1]
    ):
        return False
    return True


def messages(msg_id):
    """
    load a message from message library with specified language

    Args:
        msg_id: message id

    Returns:
        the message content in the selected language if
        message found otherwise return message in English
    """
    return message_cache[str(msg_id)]


def __input_msg(content):
    """
    build the input message to get input from usernames

    Args:
        content: content of the message

    Returns:
        the message in input structure
    """

    return (
            color.color("yellow")
            + "[+] "
            + color.color("green")
            + content
            + color.color("reset")
    )


def info(
        content,
        output_file=None,
        mode=None,
        event=None,
        language=None,
        thread_tmp_filename=None,
):
    """
    build the info message, log the message in database if requested,
    rewrite the thread temporary file

    Args:
        content: content of the message
        output_file: log filename name
        mode: write mode, [w, w+, wb, a, ab, ...]
        event: standard event in JSON structure
        language: the language
        thread_tmp_filename: thread temporary filename

    Returns:
        None
    """
    if is_not_run_from_api():  # prevent to stdout if run from API
        sys.stdout.buffer.write(
            bytes(
                color.color("yellow")
                + "[+] "
                + color.color("green")
                + content
                + color.color("reset")
                + "\n",
                "utf8",
            )
        )
    if event:  # if an event is present log it
        from core.log import __log_into_file

        __log_into_file(output_file, mode, json.dumps(event), language)
        if (
                thread_tmp_filename
        ):  # if thread temporary filename present, rewrite it
            __log_into_file(thread_tmp_filename, "w", "0", language)


def write(content):
    """
    simple print a message

    Args:
        content: content of the message

    Returns:
        None
    """
    if is_not_run_from_api():
        sys.stdout.buffer.write(
            bytes(content, "utf8") if isinstance(content, str) else content
        )


def warn(content):
    """
    build the warn message

    Args:
        content: content of the message

    Returns:
        the message in warn structure - None
    """
    if is_not_run_from_api():
        sys.stdout.buffer.write(
            bytes(
                color.color("blue")
                + "[!] "
                + color.color("yellow")
                + content
                + color.color("reset")
                + "\n",
                "utf8",
            )
        )


def error(content):
    """
    build the error message

    Args:
        content: content of the message

    Returns:
        the message in error structure - None
    """
    data = (
        color.color("red")
        + "[X] "
        + color.color("yellow")
        + content
        + color.color("reset")
        + "\n"
    )
    sys.stdout.buffer.write(data.encode("utf8"))


def write_to_api_console(content):
    """
    simple print a message in API mode

    Args:
        content: content of the message

    Returns:
        None
    """
    sys.stdout.buffer.write(bytes(content, "utf8"))
