import sys

from nettacker import logger

log = logger.get_logger()


def die_success():
    """
    exit the framework with code 0
    """
    log.reset_color()
    sys.exit(0)


def die_failure(msg):
    """
    exit the framework with code 1

    Args:
        msg: the error message
    """

    log.error(msg)
    log.reset_color()
    sys.exit(1)
