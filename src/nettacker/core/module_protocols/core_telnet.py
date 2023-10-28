#!/usr/bin/env python
# -*- coding: utf-8 -*-

import copy
import telnetlib
# from nettacker.core.utility import reverse_and_regex_condition
from nettacker.core.utility import process_conditions
from nettacker.core.utility import get_dependent_results_from_database
from nettacker.core.utility import replace_dependent_values


# def response_conditions_matched(sub_step, response):
#     return response


class NettackTelnetLib:
    def telnet_brute_force(host, ports, usernames, passwords, timeout):
        telnet_connection = telnetlib.Telnet(host, port=int(ports), timeout=int(timeout))
        telnet_connection.read_until(b"login: ")
        telnet_connection.write(usernames + "\n")
        telnet_connection.read_until(b"Password: ")
        telnet_connection.write(passwords + "\n")
        telnet_connection.close()
        return {
            "host": host,
            "username": usernames,
            "password": passwords,
            "port": ports
        }


class Engine:
    def run(
            sub_step,
            module_name,
            target,
            scan_unique_id,
            options,
            process_number,
            module_thread_number,
            total_module_thread_number,
            request_number_counter,
            total_number_of_requests
    ):
        backup_method = copy.deepcopy(sub_step['method'])
        backup_response = copy.deepcopy(sub_step['response'])
        del sub_step['method']
        del sub_step['response']
        if 'dependent_on_temp_event' in backup_response:
            temp_event = get_dependent_results_from_database(
                target,
                module_name,
                scan_unique_id,
                backup_response['dependent_on_temp_event']
            )
            sub_step = replace_dependent_values(
                sub_step,
                temp_event
            )
        action = getattr(NettackTelnetLib, backup_method, None)
        for _ in range(options['retries']):
            try:
                response = action(**sub_step)
                break
            except Exception as _:
                response = []
        sub_step['method'] = backup_method
        sub_step['response'] = backup_response
        sub_step['response']['conditions_results'] = response
        # sub_step['response']['conditions_results'] = response_conditions_matched(sub_step, response)
        return process_conditions(
            sub_step,
            module_name,
            target,
            scan_unique_id,
            options,
            response,
            process_number,
            module_thread_number,
            total_module_thread_number,
            request_number_counter,
            total_number_of_requests
        )
