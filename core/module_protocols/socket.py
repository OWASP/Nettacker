#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import copy
import re
from core.utility import reverse_and_regex_condition
from core.utility import process_conditions


def receive_all(socket_connection, limit=4196):
    """
    receive all data from a socket
    Args:
        socket_connection: python socket
        limit: limit size to get response
    Returns:
        response or b""
    """
    response_content = ""
    while len(response_content) < limit:
        try:
            response_byte = socket_connection.recv(1)
            if response_byte != b"":
                response_content += response_byte.decode()
            else:
                break
        except Exception:
            break
    return response_content


def response_conditions_matched(sub_step, response):
    conditions = sub_step['response']['conditions']
    condition_type = sub_step['response']['condition_type']
    condition_results = {}
    if sub_step['method'] == 'tcp_connect_only':
        if response:
            return response
    if sub_step['method'] == 'tcp_connect_send_and_receive':
        if response:
            received_content = response['response']
            for condition in conditions:
                regex = re.findall(re.compile(conditions[condition]['regex']), received_content)
                reverse = conditions[condition]['reverse']
                condition_results[condition] = reverse_and_regex_condition(regex, reverse)
            for condition in copy.deepcopy(condition_results):
                if not condition_results[condition]:
                    del condition_results[condition]
            if 'open_port' in condition_results and len(condition_results) > 1:
                del condition_results['open_port']
            return condition_results
    return []


class NettackerSocket:
    def tcp_connect_only(host, port, timeout):
        socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_connection.settimeout(timeout)
        socket_connection.connect((host, int(port)))
        peer_name = socket_connection.getpeername()
        socket_connection.close()
        return {
            "peer_name": peer_name,
            "service": socket.getservbyport(int(port))
        }

    def tcp_connect_send_and_receive(host, port, timeout):
        socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_connection.settimeout(timeout)
        socket_connection.connect((host, int(port)))
        peer_name = socket_connection.getpeername()
        socket_connection.send(b"ABC\x00\r\n" * 10)
        response = receive_all(socket_connection)
        socket_connection.close()
        return {
            "peer_name": peer_name,
            "service": socket.getservbyport(int(port)),
            "response": response
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
