#!/usr/bin/env python
# -*- coding: utf-8 -*-

import copy
import smtplib
# from core.utility import reverse_and_regex_condition
from core.utility import process_conditions
from core.utility import get_dependent_results_from_database
from core.utility import replace_dependent_values


# def response_conditions_matched(sub_step, response):
#     return response


class NettackSMTPLib:
    def smtp_brute_force(host, ports, usernames, passwords, timeout):
        smtp_connection = smtplib.SMTP(host, int(ports), timeout=int(timeout))
        smtp_connection.login(usernames, passwords)
        smtp_connection.close()
        return {
            "host": host,
            "username": usernames,
            "password": passwords,
            "port": ports
        }

    def smtps_brute_force(host, ports, usernames, passwords, timeout):
        smtp_connection = smtplib.SMTP(host, int(ports), timeout=int(timeout))
        smtp_connection.starttls()
        smtp_connection.login(usernames, passwords)
        smtp_connection.close()
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
        action = getattr(NettackSMTPLib, backup_method, None)
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
