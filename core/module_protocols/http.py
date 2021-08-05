#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import requests
import copy
from core.utility import reverse_and_regex_condition
from core.utility import process_conditions


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
        regex = re.findall(re.compile(conditions['content']['regex']), response.content.decode(errors='ignore'))
        reverse = conditions['content']['reverse']
        condition_results['content'] = reverse_and_regex_condition(regex, reverse)
    if 'headers' in conditions:
        condition_results['headers'] = {}
        for header in conditions['headers']:
            reverse = conditions['headers'][header]['reverse']
            if header in response.headers:
                regex = re.findall(
                    re.compile(conditions['headers'][header]['regex']),
                    response.headers[header]
                )
                condition_results['headers'][header] = reverse_and_regex_condition(regex, reverse)
            else:
                regex = re.findall(
                    re.compile(conditions['headers'][header]['regex']),
                    ""
                )
                condition_results['headers'][header] = reverse_and_regex_condition(regex, reverse) if reverse else []
    if 'responsetime' in conditions:
        if conditions['responsetime'].startswith(">="):
            condition_results['responsetime'] = response.elapsed.total_seconds() if (
                    response.elapsed.total_seconds() >= float(conditions['responsetime'].split()[-1])
            ) else []
        if conditions['responsetime'].startswith("=="):
            condition_results['responsetime'] = response.elapsed.total_seconds() if (
                    response.elapsed.total_seconds() == float(conditions['responsetime'].split()[-1])
            ) else []
        if conditions['responsetime'].startswith("<="):
            condition_results['responsetime'] = response.elapsed.total_seconds() if (
                    response.elapsed.total_seconds() <= float(conditions['responsetime'].split()[-1])
            ) else []
        if conditions['responsetime'].startswith("!="):
            condition_results['responsetime'] = response.elapsed.total_seconds() if (
                    response.elapsed.total_seconds() != float(conditions['responsetime'].split()[-1])
            ) else []
        if conditions['responsetime'].startswith("<"):
            condition_results['responsetime'] = response.elapsed.total_seconds() if (
                    response.elapsed.total_seconds() < float(conditions['responsetime'].split()[-1])
            ) else []
        if conditions['responsetime'].startswith(">"):
            condition_results['responsetime'] = response.elapsed.total_seconds() if (
                    response.elapsed.total_seconds() > float(conditions['responsetime'].split()[-1])
            ) else []
    if condition_type.lower() == "or":
        # if one of the values are matched, it will be a string or float object in the array
        # we count False in the array and if it's not all []; then we know one of the conditions is matched.
        if (
                'headers' not in condition_results and
                (
                        list(condition_results.values()).count([]) != len(list(condition_results.values()))
                )
        ) or (
                'headers' in condition_results and
                (
                        (
                                list(condition_results.values()).count([]) - 1 !=
                                len(list(condition_results.values()))
                        ) and
                        (
                                list(condition_results['headers'].values()).count([]) !=
                                len(list(condition_results['headers'].values()))
                        )
                )
        ):
            return condition_results
        else:
            return []
    if condition_type.lower() == "and":
        if [] in condition_results.values() or \
                ('headers' in condition_results and [] in condition_results['headers'].values()):
            return []
        else:
            return condition_results
    return []


class engine:
    def run(sub_step, module_name, target, scan_unique_id, options):
        backup_method = copy.deepcopy(sub_step['method'])
        backup_response = copy.deepcopy(sub_step['response'])
        action = getattr(requests, backup_method, None)
        del sub_step['method']
        del sub_step['response']
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
