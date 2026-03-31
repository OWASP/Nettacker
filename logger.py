import sys
from enum import Enum
from functools import cached_property

from nettacker.core.utils import time


class TerminalCodes(Enum):
    RESET = "\033[0m"

    # Colors \033[1;
    GREY = "\033[1;30m"
    RED = "\033[1;31m"
    GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[1;34m"
    PURPLE = "\033[1;35m"
    CYAN = "\033[1;36m"
    WHITE = "\033[1;37m"


class Logger:
    """Nettacker logger."""

    @staticmethod
    def log(text):
        print(text, end="", flush=True)  # noqa: T201

    @cached_property
    def run_from_api(self):
        """
        check if framework run from API to prevent any alert

        Returns:
            True if run from API otherwise False
        """
        return "--start-api" in sys.argv

    @cached_property
    def verbose_mode_is_enabled(self):
        return "--verbose" in sys.argv or "-v" in sys.argv

    @cached_property
    def event_verbose_mode_is_enabled(self):
        return "--verbose-event" in sys.argv

    def info(self, content):
        """
        build the info message, log the message in database if requested,
        rewrite the thread temporary file

        Args:
            content: content of the message

        Returns:
            None
        """
        if not self.run_from_api:
            self.log(
                TerminalCodes.YELLOW.value
                + "[{0}][+] ".format(time.now())
                + TerminalCodes.GREEN.value
                + content
                + TerminalCodes.RESET.value
                + "\n",
            )

    def verbose_event_info(self, content):
        """
        build the info message, log the message in database if requested,
        rewrite the thread temporary file

        Args:
            content: content of the message

        Returns:
            None
        """
        if not self.run_from_api and (
            self.verbose_mode_is_enabled or self.event_verbose_mode_is_enabled
        ):  # prevent to stdout if run from API
            self.log(
                TerminalCodes.YELLOW.value
                + "[{0}][+] ".format(time.now())
                + TerminalCodes.GREEN.value
                + content
                + TerminalCodes.RESET.value
                + "\n",
            )

    def write(self, content):
        """
        simple print a message

        Args:
            content: content of the message

        Returns:
            None
        """
        if not self.run_from_api:
            self.log(content)

    def success_event_info(self, content):
        """
        build the info message, log the message in database if requested,
        rewrite the thread temporary file

        Args:
            content: content of the message

        Returns:
            None
        """
        if not self.run_from_api:
            self.log(
                TerminalCodes.RED.value
                + "[{0}][+++] ".format(time.now())
                + TerminalCodes.CYAN.value
                + content
                + TerminalCodes.RESET.value
                + "\n",
            )

    def verbose_info(self, content):
        """
        build the info message, log the message in database if requested,
        rewrite the thread temporary file

        Args:
            content: content of the message

        Returns:
            None
        """
        if self.verbose_mode_is_enabled:
            self.log(
                TerminalCodes.YELLOW.value
                + "[{0}][+] ".format(time.now())
                + TerminalCodes.PURPLE.value
                + content
                + TerminalCodes.RESET.value
                + "\n",
            )

    def warn(self, content):
        """
        build the warn message

        Args:
            content: content of the message

        Returns:
            the message in warn structure - None
        """
        if not self.run_from_api:
            self.log(
                TerminalCodes.BLUE.value
                + "[{0}][!] ".format(time.now())
                + TerminalCodes.YELLOW.value
                + content
                + TerminalCodes.RESET.value
                + "\n",
            )

    def error(self, content):
        """
        build the error message

        Args:
            content: content of the message

        Returns:
            the message in error structure - None
        """
        self.log(
            TerminalCodes.RED.value
            + "[{0}][X] ".format(time.now())
            + TerminalCodes.YELLOW.value
            + content
            + TerminalCodes.RESET.value
            + "\n"
        )

    def write_to_api_console(self, content):
        """
        simple print a message in API mode

        Args:
            content: content of the message

        Returns:
            None
        """
        self.log(content)

    def reset_color(self):
        self.log(TerminalCodes.RESET.value)


def get_logger():
    return Logger()
