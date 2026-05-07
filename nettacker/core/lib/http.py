#!/usr/bin/env python

import asyncio
import copy
import hashlib
import random
import re
import time
from urllib.parse import urlsplit, urlunsplit

import aiohttp
import uvloop

from nettacker.core.lib.base import BaseEngine
from nettacker.core.utils.common import (
    get_http_header_key,
    get_http_header_value,
    replace_dependent_response,
    reverse_and_regex_condition,
)

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

SIMPLE_RESPONSE_CONDITIONS = (
    "reason",
    "status_code",
    "content",
    "url",
    "content_length",
    "content_sha1",
)


def _content_fingerprint(content):
    return {
        "content_length": str(len(content)),
        "content_sha1": hashlib.sha1(content).hexdigest(),
    }


def _random_baseline_url(url, segment_length=12):
    parts = urlsplit(url)
    random_segment = "nettacker-" + "".join(
        random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(segment_length)
    )
    path = parts.path or "/"
    directory = path.rstrip("/").rsplit("/", 1)[0]
    baseline_path = f"{directory}/{random_segment}" if directory else f"/{random_segment}"
    if path.endswith("/"):
        baseline_path += "/"
    return urlunsplit((parts.scheme, parts.netloc, baseline_path, "", ""))


def _baseline_response_diff(response, baseline_response, options):
    if not baseline_response:
        return []

    max_length_delta = int(options.get("max_content_length_delta", 64))
    differences = []
    if response["status_code"] != baseline_response["status_code"]:
        differences.append("status_code")

    length_delta = abs(
        int(response.get("content_length", 0)) - int(baseline_response.get("content_length", 0))
    )
    if length_delta > max_length_delta:
        differences.append("content_length")

    if response.get("content_sha1") != baseline_response.get("content_sha1"):
        differences.append("content_sha1")

    return differences


async def perform_request_action(action, request_options):
    start_time = time.time()
    async with action(**request_options) as response:
        content = await response.content.read()
        return {
            "reason": response.reason,
            "url": str(response.url),
            "status_code": str(response.status),
            "content": content,
            **_content_fingerprint(content),
            "headers": dict(response.headers),
            "responsetime": time.time() - start_time,
        }


async def send_request(request_options, method):
    async with aiohttp.ClientSession() as session:
        action = getattr(session, method, None)
        response = await asyncio.gather(
            *[asyncio.ensure_future(perform_request_action(action, request_options))]
        )
        return response[0]


def response_conditions_matched(sub_step, response):
    if not response:
        return {}
    condition_type = sub_step["response"]["condition_type"]
    conditions = sub_step["response"]["conditions"]
    condition_results = {}
    for condition in conditions:
        if condition in SIMPLE_RESPONSE_CONDITIONS:
            regex = re.findall(re.compile(conditions[condition]["regex"]), response[condition])
            reverse = conditions[condition]["reverse"]
            condition_results[condition] = reverse_and_regex_condition(regex, reverse)
        if condition == "baseline_response":
            condition_results[condition] = _baseline_response_diff(
                response,
                response.get("baseline_response"),
                conditions[condition],
            )
        if condition == "headers":
            # convert headers to case insensitive dict
            for key in response["headers"].copy():
                response["headers"][key.lower()] = response["headers"][key]
            condition_results["headers"] = {}
            for header in conditions["headers"]:
                reverse = conditions["headers"][header]["reverse"]
                try:
                    regex = re.findall(
                        re.compile(conditions["headers"][header]["regex"]),
                        response["headers"][header.lower()]
                        if header.lower() in response["headers"]
                        else "",
                    )
                    condition_results["headers"][header] = reverse_and_regex_condition(
                        regex, reverse
                    )
                except TypeError:
                    condition_results["headers"][header] = []
        if condition == "responsetime":
            if len(conditions[condition].split()) == 2 and conditions[condition].split()[0] in [
                "==",
                "!=",
                ">=",
                "<=",
                ">",
                "<",
            ]:
                exec(
                    "condition_results['responsetime'] = response['responsetime'] if ("
                    + "response['responsetime'] {0} float(conditions['responsetime'].split()[-1])".format(
                        conditions["responsetime"].split()[0]
                    )
                    + ") else []"
                )
            else:
                condition_results["responsetime"] = []
    if condition_type.lower() == "or":
        # if one of the values are matched, it will be a string or float object in the array
        # we count False in the array and if it's not all []; then we know one of the conditions
        # is matched.
        if (
            "headers" not in condition_results
            and (
                list(condition_results.values()).count([]) != len(list(condition_results.values()))
            )
        ) or (
            "headers" in condition_results
            and (
                len(list(condition_results.values()))
                + len(list(condition_results["headers"].values()))
                - list(condition_results.values()).count([])
                - list(condition_results["headers"].values()).count([])
                - 1
                != 0
            )
        ):
            if sub_step["response"].get("log", False):
                condition_results["log"] = sub_step["response"]["log"]
                if "response_dependent" in condition_results["log"]:
                    condition_results["log"] = replace_dependent_response(
                        condition_results["log"], condition_results
                    )
            return condition_results
        else:
            return {}
    if condition_type.lower() == "and":
        if [] in condition_results.values() or (
            "headers" in condition_results and [] in condition_results["headers"].values()
        ):
            return {}
        else:
            if sub_step["response"].get("log", False):
                condition_results["log"] = sub_step["response"]["log"]
                if "response_dependent" in condition_results["log"]:
                    condition_results["log"] = replace_dependent_response(
                        condition_results["log"], condition_results
                    )
            return condition_results
    return {}


class HttpEngine(BaseEngine):
    def run(
        self,
        sub_step,
        module_name,
        target,
        scan_id,
        options,
        process_number,
        module_thread_number,
        total_module_thread_number,
        request_number_counter,
        total_number_of_requests,
    ):
        if options["http_header"] is not None:
            for header in options["http_header"]:
                key = get_http_header_key(header).strip()
                value = get_http_header_value(header)
                if value is not None:
                    sub_step["headers"][key] = value.strip()
                else:
                    sub_step["headers"][key] = ""
        backup_method = copy.deepcopy(sub_step["method"])
        backup_response = copy.deepcopy(sub_step["response"])
        backup_baseline_response = copy.deepcopy(
            sub_step["response"]["conditions"].get("baseline_response", None)
        )
        backup_iterative_response_match = copy.deepcopy(
            sub_step["response"]["conditions"].get("iterative_response_match", None)
        )
        if options["user_agent"] == "random_user_agent":
            sub_step["headers"]["User-Agent"] = random.choice(options["user_agents"])
        del sub_step["method"]
        if "dependent_on_temp_event" in backup_response:
            temp_event = self.get_dependent_results_from_database(
                target,
                module_name,
                scan_id,
                backup_response["dependent_on_temp_event"],
            )
            sub_step = self.replace_dependent_values(sub_step, temp_event)
        backup_response = copy.deepcopy(sub_step["response"])
        del sub_step["response"]
        for _i in range(options["retries"]):
            try:
                response = asyncio.run(send_request(sub_step, backup_method))
                response["content"] = response["content"].decode(errors="ignore")
                break
            except Exception:
                response = []
        sub_step["method"] = backup_method
        sub_step["response"] = backup_response

        if backup_iterative_response_match is not None:
            backup_iterative_response_match = copy.deepcopy(
                sub_step["response"]["conditions"].get("iterative_response_match")
            )
            del sub_step["response"]["conditions"]["iterative_response_match"]

        if response and backup_baseline_response is not None:
            baseline_request = copy.deepcopy(sub_step)
            del baseline_request["method"]
            del baseline_request["response"]
            baseline_request["url"] = _random_baseline_url(
                baseline_request["url"],
                int(backup_baseline_response.get("random_path_segment_length", 12)),
            )
            for _i in range(options["retries"]):
                try:
                    baseline_response = asyncio.run(send_request(baseline_request, backup_method))
                    baseline_response["content"] = baseline_response["content"].decode(
                        errors="ignore"
                    )
                    response["baseline_response"] = baseline_response
                    break
                except Exception:
                    response["baseline_response"] = []

        sub_step["response"]["conditions_results"] = response_conditions_matched(
            sub_step, response
        )

        if backup_iterative_response_match is not None and (
            sub_step["response"]["conditions_results"]
            or sub_step["response"]["condition_type"] == "or"
        ):
            sub_step["response"]["conditions"][
                "iterative_response_match"
            ] = backup_iterative_response_match
            for key in sub_step["response"]["conditions"]["iterative_response_match"]:
                result = response_conditions_matched(
                    sub_step["response"]["conditions"]["iterative_response_match"][key],
                    response,
                )
                if result:
                    sub_step["response"]["conditions_results"][key] = result

        return self.process_conditions(
            sub_step,
            module_name,
            target,
            scan_id,
            options,
            response,
            process_number,
            module_thread_number,
            total_module_thread_number,
            request_number_counter,
            total_number_of_requests,
        )
