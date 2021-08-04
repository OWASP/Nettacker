#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import copy
import re
from core.utility import reverse_and_regex_condition
from core.utility import process_conditions


def response_conditions_matched(sub_step, response):
    if sub_step['method'] == 'tcp_connect_only':
        if response:
            return response
    return []


class NettackerSocket:
    def tcp_connect_only(host, port, timeout):
        socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_connection.settimeout(timeout)
        socket_connection.connect((host, int(port)))
        socket_connection.close()
        return {
            "peer_name": socket_connection.getpeername(),
            "service": socket.getservbyport(int(port))
        }


class engine:
    def run(sub_step, module_name, target, scan_unique_id, options):
        backup_method = copy.deepcopy(sub_step['method'])
        backup_response = copy.deepcopy(sub_step['response'])
        del sub_step['method']
        del sub_step['response']
        action = getattr(NettackerSocket, backup_method, None)
        try:
            response = action(**sub_step)
        except Exception:
            response = None
        sub_step['method'] = backup_method
        sub_step['response'] = backup_response
        sub_step['response']['conditions_results'] = response_conditions_matched(sub_step, response)
        return process_conditions(
            sub_step,
            module_name,
            target,
            scan_unique_id,
            options
        )
