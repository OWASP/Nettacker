#!/usr/bin/env python
# -*- coding: utf-8 -*-

from subprocess import PIPE, Popen
import copy
import re
import datetime
from core.utility import reverse_and_regex_condition
from core.utility import process_conditions
from core.utility import get_dependent_results_from_database
from core.utility import replace_dependent_values


def response_conditions_matched(sub_step, response):
    conditions = sub_step['response']['conditions']
    condition_type = sub_step['response']['condition_type']
    condition_results = {}
    if sub_step['method'] == 'os_command':
        if response:
            response = response.decode()
            for condition in conditions:
                if condition == 'END_DATE':
                    try:
                        operation = conditions[condition]['regex'].split()[0]
                        seconds = float(conditions[condition]['regex'].split()[1])
                        if operation in [">", "<", ">=", "<=", "=="]:
                            response = re.findall("expires `.*UTC'", response)[0][9:]
                            end_date = datetime.datetime.strptime(response[:-1], '%Y-%m-%d %H:%M:%S %Z').timestamp()
                            now_date = datetime.datetime.now().timestamp()
                            delta = float(end_date - now_date)
                            condition_results[condition] = response if eval(
                                "{delta} {operation} {seconds}".format(
                                    delta=delta,
                                    operation=operation,
                                    seconds=seconds
                                )
                            ) else False
                    except Exception:
                        condition_results[condition] = False
                else:
                    regex = re.findall(re.compile(conditions[condition]['regex']), response)
                    reverse = conditions[condition]['reverse']
                    condition_results[condition] = regex or response if reverse_and_regex_condition(regex,
                                                                                                    reverse) else []
            for condition in copy.deepcopy(condition_results):
                if not condition_results[condition]:
                    del condition_results[condition]
            if condition_type == 'and':
                return condition_results if len(condition_results) == len(conditions) else []
            if condition_type == 'or':
                return condition_results if condition_results else []
    return []


class NettackerExecute:
    def os_command(command):
        p = Popen(command.split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()
        response = stdout + stderr
        return response


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
        del sub_step["method"]
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
        action = getattr(NettackerExecute, backup_method, None)
        backup_command = sub_step['command']
        if options['socks_configuration_file']:
            sub_step['command'] = "proxychains4 -f " + options['socks_configuration_file'] + ' ' + sub_step['command']
        for _ in range(options['retries']):
            try:
                response = action(**sub_step)
                break
            except Exception:
                response = []
        sub_step['command'] = backup_command
        sub_step['method'] = backup_method
        sub_step['response'] = backup_response
        sub_step['response']['conditions_results'] = response_conditions_matched(sub_step, response)
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
