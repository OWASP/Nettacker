#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import copy

from core.ip import (get_ip_range,
                     generate_ip_range,
                     is_single_ipv4,
                     is_ipv4_range,
                     is_ipv4_cidr,
                     is_single_ipv6,
                     is_ipv6_range,
                     is_ipv6_cidr)
from core.module_protocols import http
from core.module_protocols import socket


def expand_targets(options):
    """
    analysis and calulcate targets.

    Args:
        options: all options

    Returns:
        a generator
    """

    targets = []
    for target in options.targets:
        if '://' in target:
            # remove url proto; uri; port
            target = target.split('://')[1].split('/')[0].split(':')[0]
            targets.append(target)
        # single IPs
        elif is_single_ipv4(target) or is_single_ipv6(target):
            if options.scan_ip_range:
                targets += get_ip_range(target)
            else:
                targets.append(target)
        # IP ranges
        elif is_ipv4_range(target) or is_ipv6_range(target) or is_ipv4_cidr(target) or is_ipv6_cidr(target):
            targets += generate_ip_range(target)
        # domains
        elif options.scan_subdomains:
            # todo: add subdoamin scan here
            # run: subdomain_scan(target)
            # targets += targets
            targets.append(target)
        else:
            targets.append(target)
    if options.ping_before_scan:
        for target in copy.deepcopy(targets):
            # todo: add icmp scan here
            # if ping failed;  targets.remove(target)
            pass
    return targets
