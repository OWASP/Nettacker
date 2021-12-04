#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import copy
import json
import os
from core.ip import (get_ip_range,
                     generate_ip_range,
                     is_single_ipv4,
                     is_ipv4_range,
                     is_ipv4_cidr,
                     is_single_ipv6,
                     is_ipv6_range,
                     is_ipv6_cidr)
from database.db import find_events


def filter_target_by_event(targets, scan_unique_id, module_name):
    for target in copy.deepcopy(targets):
        if not find_events(target, module_name, scan_unique_id):
            targets.remove(target)
    return targets


def expand_targets(options, scan_unique_id):
    """
    analysis and calulcate targets.

    Args:
        options: all options
        scan_unique_id: unique scan identifier

    Returns:
        a generator
    """
    from core.scan_targers import multi_processor
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
        # domains probably
        else:
            targets.append(target)
    options.targets = targets

    # subdomain_scan
    if options.scan_subdomains:
        selected_modules = options.selected_modules
        options.selected_modules = ['subdomain_scan']
        multi_processor(
            copy.deepcopy(options),
            scan_unique_id
        )
        options.selected_modules = selected_modules
        if 'subdomain_scan' in options.selected_modules:
            options.selected_modules.remove('subdomain_scan')

        for target in copy.deepcopy(options.targets):
            for row in find_events(target, 'subdomain_scan', scan_unique_id):
                for sub_domain in json.loads(row.json_event)['response']['conditions_results']['content']:
                    if sub_domain not in options.targets:
                        options.targets.append(sub_domain)
    # icmp_scan
    if options.ping_before_scan:
        if os.geteuid() == 0:
            selected_modules = options.selected_modules
            options.selected_modules = ['icmp_scan']
            multi_processor(
                copy.deepcopy(options),
                scan_unique_id
            )
            options.selected_modules = selected_modules
            if 'icmp_scan' in options.selected_modules:
                options.selected_modules.remove('icmp_scan')
            options.targets = filter_target_by_event(targets, scan_unique_id, 'icmp_scan')
        else:
            from core.alert import warn
            from core.alert import messages
            warn(messages("icmp_need_root_access"))
            if 'icmp_scan' in options.selected_modules:
                options.selected_modules.remove('icmp_scan')
    # port_scan
    if not options.skip_service_discovery:
        options.skip_service_discovery = True
        selected_modules = options.selected_modules
        options.selected_modules = ['port_scan']
        multi_processor(
            copy.deepcopy(options),
            scan_unique_id
        )
        options.selected_modules = selected_modules
        if 'port_scan' in options.selected_modules:
            options.selected_modules.remove('port_scan')
        options.targets = filter_target_by_event(targets, scan_unique_id, 'port_scan')
        options.skip_service_discovery = False
    return list(set(options.targets))
