#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
from core import compatible

os_name = compatible.os_name()


def finish():
    """
    reset the color of windows/terminal before exit
    """
    if "linux" in os_name or os_name == "darwin":
        sys.stdout.write("\033[0m")
    else:
        import ctypes
        std_out_handle = ctypes.windll.kernel32.GetStdHandle(-11)
        handle = std_out_handle
        ctypes.windll.kernel32.SetConsoleTextAttribute(handle, 7)


def color(color):
    """
    colors for terminal and windows cmd

    Args:
        color: color name

    Returns:
        color values or empty string
    """
    if "linux" in os_name or os_name == "darwin":
        if color == "reset":
            return "\033[0m"
        if color == "grey":
            return "\033[1;30m"
        if color == "red":
            return "\033[1;31m"
        if color == "green":
            return "\033[1;32m"
        if color == "yellow":
            return "\033[1;33m"
        if color == "blue":
            return "\033[1;34m"
        if color == "purple":
            return "\033[1;35m"
        if color == "cyan":
            return "\033[1;36m"
        if color == "white":
            return "\033[1;37m"
    else:
        import ctypes
        std_out_handle = ctypes.windll.kernel32.GetStdHandle(-11)
        handle = std_out_handle
        if color == "reset":
            pass
        if color == "grey":
            ctypes.windll.kernel32.SetConsoleTextAttribute(handle, 0x07)
        if color == "red":
            ctypes.windll.kernel32.SetConsoleTextAttribute(handle, 12)
        if color == "green":
            ctypes.windll.kernel32.SetConsoleTextAttribute(handle, 10)
        if color == "yellow":
            ctypes.windll.kernel32.SetConsoleTextAttribute(handle, 0x06)
        if color == "blue":
            ctypes.windll.kernel32.SetConsoleTextAttribute(handle, 0x09)
        if color == "purple":
            ctypes.windll.kernel32.SetConsoleTextAttribute(handle, 13)
        if color == "cyan":
            ctypes.windll.kernel32.SetConsoleTextAttribute(handle, 11)
        if color == "white":
            ctypes.windll.kernel32.SetConsoleTextAttribute(handle, 0x07)
    return ""
