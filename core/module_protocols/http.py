#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import requests
import copy
import json
from core.alert import (info,
                        verbose_info)


def reverse_and_regex_condition(regex, reverse):
    if regex:
        if reverse:
            return []
        return list(set(regex))
    else:
        if reverse:
            return list(set(regex))
        return []


def response_conditions_matched(sub_step, response):
    condition_type = sub_step['response']['condition_type']
    conditions = sub_step['response']['conditions']
    condition_results = {}
    if 'reason' in conditions:
        regex = re.findall(re.compile(conditions['reason']['regex']), response.reason)
        reverse = conditions['reason']['reverse']
        condition_results['reason'] = reverse_and_regex_condition(regex, reverse)
    if 'status_code' in conditions:
        regex = re.findall(re.compile(conditions['status_code']['regex']), str(response.status_code))
        reverse = conditions['status_code']['reverse']
        condition_results['status_code'] = reverse_and_regex_condition(regex, reverse)
    if 'content' in conditions:
        regex = re.findall(re.compile(conditions['content']['regex']), response.content.decode())
        reverse = conditions['content']['reverse']
        condition_results['content'] = reverse_and_regex_condition(regex, reverse)
    if 'headers' in conditions:
        for header in conditions['headers']:
            if header in response.headers:
                regex = re.findall(
                    re.compile(conditions['headers'][header]['regex']),
                    response.headers[header]
                )
                reverse = conditions['headers'][header]['reverse']
                condition_results['headers'] = reverse_and_regex_condition(regex, reverse)
    if 'responsetime' in conditions:
        if conditions['responsetime'].startswith(">="):
            condition_results['responsetime'] = response.elapsed.total_seconds() if (
                    response.elapsed.total_seconds() >= float(conditions['responsetime'].split()[-1])
            ) else False
        if conditions['responsetime'].startswith("=="):
            condition_results['responsetime'] = response.elapsed.total_seconds() if (
                    response.elapsed.total_seconds() == float(conditions['responsetime'].split()[-1])
            ) else False
        if conditions['responsetime'].startswith("<="):
            condition_results['responsetime'] = response.elapsed.total_seconds() if (
                    response.elapsed.total_seconds() <= float(conditions['responsetime'].split()[-1])
            ) else False
        if conditions['responsetime'].startswith("!="):
            condition_results['responsetime'] = response.elapsed.total_seconds() if (
                    response.elapsed.total_seconds() != float(conditions['responsetime'].split()[-1])
            ) else False
        if conditions['responsetime'].startswith("<"):
            condition_results['responsetime'] = response.elapsed.total_seconds() if (
                    response.elapsed.total_seconds() < float(conditions['responsetime'].split()[-1])
            ) else False
        if conditions['responsetime'].startswith(">"):
            condition_results['responsetime'] = response.elapsed.total_seconds() if (
                    response.elapsed.total_seconds() > float(conditions['responsetime'].split()[-1])
            ) else False
    if condition_type.lower() == "or":
        # if one of the values are matched, it will be a string or float object in the array
        # we count False in the array and if it's not all []; then we know one of the conditions is matched.
        if list(condition_results.values()).count([]) != len(list(condition_results.values())):
            return condition_results
        else:
            return []
    if condition_type.lower() == "and":
        if [] in condition_results.values():
            return []
        else:
            return condition_results
    return []


class engine:
    def run(sub_step, payload):
        request_lib = requests.session() if payload['session'] is True else requests
        action = getattr(request_lib, sub_step['method'], None)

        backup_method = copy.deepcopy(sub_step['method'])
        backup_response = copy.deepcopy(sub_step['response'])
        del sub_step['method']
        del sub_step['response']
        try:
            response = action(**sub_step)
        except Exception:
            return False
        sub_step['method'] = backup_method
        sub_step['response'] = backup_response
        conditions_results = response_conditions_matched(sub_step, response)
        if conditions_results:
            info(
                json.dumps(sub_step) + ' ' + json.dumps(conditions_results)
            )
            return True
        else:
            verbose_info(
                json.dumps(sub_step) + ' ' + str(conditions_results)
            )
            return False
