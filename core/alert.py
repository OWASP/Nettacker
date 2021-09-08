#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from core import color
from core.messages import load_message
from core.time import now

message_cache = load_message().messages


def run_from_api():
    """
    check if framework run from API to prevent any alert

    Returns:
        True if run from API otherwise False
    """
    return "--start-api" in sys.argv


def verbose_mode_is_enabled():
    return '--verbose' in sys.argv or '-v' in sys.argv


def event_verbose_mode_is_enabled():
    return '--verbose-event' in sys.argv


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


def info(content):
    """
    build the info message, log the message in database if requested,
    rewrite the thread temporary file

    Args:
        content: content of the message

    Returns:
        None
    """
    if not run_from_api():
        sys.stdout.buffer.write(
            bytes(
                color.color("yellow")
                + "[{0}][+] ".format(now())
                + color.color("green")
                + content
                + color.color("reset")
                + "\n",
                "utf8",
            )
        )
        sys.stdout.flush()


def verbose_event_info(content):
    """
    build the info message, log the message in database if requested,
    rewrite the thread temporary file

    Args:
        content: content of the message

    Returns:
        None
    """
    if (not run_from_api()) and (
            verbose_mode_is_enabled() or event_verbose_mode_is_enabled()
    ):  # prevent to stdout if run from API
        sys.stdout.buffer.write(
            bytes(
                color.color("yellow")
                + "[{0}][+] ".format(now())
                + color.color("green")
                + content
                + color.color("reset")
                + "\n",
                "utf8",
            )
        )
        sys.stdout.flush()


def success_event_info(content):
    """
    build the info message, log the message in database if requested,
    rewrite the thread temporary file

    Args:
        content: content of the message

    Returns:
        None
    """
    if not run_from_api():
        sys.stdout.buffer.write(
            bytes(
                color.color("red")
                + "[{0}][+++] ".format(now())
                + color.color("cyan")
                + content
                + color.color("reset")
                + "\n",
                "utf8",
            )
        )
        sys.stdout.flush()


def verbose_info(content):
    """
    build the info message, log the message in database if requested,
    rewrite the thread temporary file

    Args:
        content: content of the message

    Returns:
        None
    """
    if verbose_mode_is_enabled():
        sys.stdout.buffer.write(
            bytes(
                color.color("yellow")
                + "[{0}][+] ".format(now())
                + color.color("purple")
                + content
                + color.color("reset")
                + "\n",
                "utf8",
            )
        )
        sys.stdout.flush()


def write(content):
    """
    simple print a message

    Args:
        content: content of the message

    Returns:
        None
    """
    if not run_from_api():
        sys.stdout.buffer.write(
            bytes(content, "utf8") if isinstance(content, str) else content
        )
    sys.stdout.flush()


def warn(content):
    """
    build the warn message

    Args:
        content: content of the message

    Returns:
        the message in warn structure - None
    """
    if not run_from_api():
        sys.stdout.buffer.write(
            bytes(
                color.color("blue")
                + "[{0}][!] ".format(now())
                + color.color("yellow")
                + content
                + color.color("reset")
                + "\n",
                "utf8",
            )
        )
    sys.stdout.flush()


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
            + "[{0}][X] ".format(now())
            + color.color("yellow")
            + content
            + color.color("reset")
            + "\n"
    )
    sys.stdout.buffer.write(data.encode("utf8"))
    sys.stdout.flush()


def write_to_api_console(content):
    """
    simple print a message in API mode

    Args:
        content: content of the message

    Returns:
        None
    """
    sys.stdout.buffer.write(bytes(content, "utf8"))
    sys.stdout.flush()
