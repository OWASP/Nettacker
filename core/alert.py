
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import argparse
import logging
from core import color
from core.messages import load_message
from core.time import now

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

message_cache = load_message().messages


def run_from_api():
    """
    Check if the framework runs from API to prevent any alerts.

    Returns:
        True if run from API, otherwise False.
    """
    return "--start-api" in sys.argv


def verbose_mode_is_enabled():
    return '--verbose' in sys.argv or '-v' in sys.argv


def event_verbose_mode_is_enabled():
    return '--verbose-event' in sys.argv


def messages(msg_id):
    """
    Load a message from the message library with specified language.

    Args:
        msg_id: message id

    Returns:
        The message content in the selected language if
        the message is found; otherwise, return the message in English.
    """
    return message_cache.get(str(msg_id), "Message not found in cache.")


def info(content):
    """
    Build the info message, log the message, and write to stdout.

    Args:
        content: content of the message

    Returns:
        None
    """
    if not run_from_api():
        log_message = f"[{now()}][+] {content}"
        logger.info(log_message)
        print(color.color("yellow") + log_message + color.color("reset"))


def verbose_event_info(content):
    """
    Build the info message, log the message, and write to stdout if verbose mode is enabled.

    Args:
        content: content of the message

    Returns:
        None
    """
    if not run_from_api() and (verbose_mode_is_enabled() or event_verbose_mode_is_enabled()):
        log_message = f"[{now()}][+] {content}"
        logger.info(log_message)
        print(color.color("yellow") + log_message + color.color("reset"))


# Add similar improvements to other functions...

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Your script description here.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose mode.")
    parser.add_argument("--verbose-event", action="store_true", help="Enable verbose event mode.")
    parser.add_argument("--start-api", action="store_true", help="Run from API.")
    args = parser.parse_args()

    # You can access command-line arguments using args.verbose, args.verbose_event, and args.start_api
    # Example: if args.verbose:
    #            verbose_mode_is_enabled()

    # Add the rest of your script logic here...
