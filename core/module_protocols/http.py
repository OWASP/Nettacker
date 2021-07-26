#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import requests

def reverse_and_regex_condition(regex, reverse):
    if regex:
        if reverse:
            return False
        return True
    else:
        if reverse:
            return True
        return False


def response_conditions(response, conditions):
    condition_type = conditions['condition_type']
    conditions = conditions['conditions']
    condition_results = []
    if 'reason' in conditions:
        regex = re.search(str(conditions['reason']['regex']).encode(), response.reason.encode())
        reverse = conditions['reason']['reverse']
        condition_results.append(reverse_and_regex_condition(regex, reverse))
    if 'status_code' in conditions:
        regex = re.search(str(conditions['status_code']['regex']).encode(), str(response.status_code).encode())
        reverse = conditions['status_code']['reverse']
        condition_results.append(reverse_and_regex_condition(regex, reverse))
    if 'content' in conditions:
        regex = re.search(str(conditions['content']['regex']).encode(), str(response.content).encode())
        reverse = conditions['content']['reverse']
        condition_results.append(reverse_and_regex_condition(regex, reverse))
    if 'headers' in conditions:
        for header in conditions['headers']:
            if header in response.headers:
                regex = re.search(str(conditions['headers'][header]['regex']).encode(),
                                  str(response.headers[header]).encode())
                reverse = conditions['headers'][header]['reverse']
                condition_results.append(reverse_and_regex_condition(regex, reverse))
    if 'response_time' in conditions:
        if conditions['response_time'].startswith(">="):
            condition_results.append(response.elapsed.total_seconds() >= float(conditions['response_time'].split()[-1]))
        if conditions['response_time'].startswith("=="):
            condition_results.append(response.elapsed.total_seconds() == float(conditions['response_time'].split()[-1]))
        if conditions['response_time'].startswith("<="):
            condition_results.append(response.elapsed.total_seconds() <= float(conditions['response_time'].split()[-1]))
        if conditions['response_time'].startswith("!="):
            condition_results.append(response.elapsed.total_seconds() != float(conditions['response_time'].split()[-1]))
        if conditions['response_time'].startswith("<"):
            condition_results.append(response.elapsed.total_seconds() < float(conditions['response_time'].split()[-1]))
        if conditions['response_time'].startswith(">"):
            condition_results.append(response.elapsed.total_seconds() <= float(conditions['response_time'].split()[-1]))
    if condition_type.lower() == "or":
        if True in condition_results:
            return True
        else:
            return False
    if condition_type.lower() == "and":
        if False in condition_results:
            return False
        else:
            return True
    return False


class engine:
    def run(sub_step, payload):
        request_lib = requests.session() if payload['session'] is True else requests
        action = getattr(request_lib, sub_step['method'], None)
        del sub_step['method']
        conditions = sub_step['response']
        del sub_step['response']
        # legacy code must be here
        print(sub_step, response_conditions(action(**sub_step), conditions))
