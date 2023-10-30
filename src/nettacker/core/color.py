#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys


def reset_color():
    """
    reset the color of terminal before exit
    """
    sys.stdout.write("\033[0m")


def color(color_name):
    """
    color_names for terminal and windows cmd

    Args:
        color_name: color name

    Returns:
        color_name values or empty string
    """
    if color_name == "reset":
        return "\033[0m"
    elif color_name == "grey":
        return "\033[1;30m"
    elif color_name == "red":
        return "\033[1;31m"
    elif color_name == "green":
        return "\033[1;32m"
    elif color_name == "yellow":
        return "\033[1;33m"
    elif color_name == "blue":
        return "\033[1;34m"
    elif color_name == "purple":
        return "\033[1;35m"
    elif color_name == "cyan":
        return "\033[1;36m"
    elif color_name == "white":
        return "\033[1;37m"
    return ""
