#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import copy
import json
from core.ip import (get_ip_range,
                     generate_ip_range,
                     is_single_ipv4,
                     is_ipv4_range,
                     is_ipv4_cidr,
                     is_single_ipv6,
                     is_ipv6_range,
                     is_ipv6_cidr)
from database.db import find_events


def expand_targets(options, scan_unique_id):
    """
    analysis and calulcate targets.

    Args:
        options: all options
        scan_unique_id: unique scan identifier

    Returns:
        a generator
    """
    from core.load_modules import perform_scan
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
            targets.append(target)
            perform_scan(
                options,
                target,
                'subdomain_scan',
                scan_unique_id,
                'pre_process',
                'pre_process_thread',
                'unknown'
            )
            for row in find_events(target, 'subdomain_scan', scan_unique_id):
                for sub_domain in json.loads(row.json_event)['response']['conditions_results']['content']:
                    if sub_domain not in targets:
                        targets.append(sub_domain)
        else:
            targets.append(target)
    if options.ping_before_scan:
        for target in copy.deepcopy(targets):
            perform_scan(
                options,
                target,
                'icmp_scan',
                scan_unique_id,
                'pre_process',
                'pre_process_thread',
                'unknown'
            )
            if not find_events(target, 'icmp_scan', scan_unique_id):
                targets.remove(target)
    return list(set(targets))
