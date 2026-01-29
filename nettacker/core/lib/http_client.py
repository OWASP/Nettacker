#!/usr/bin/env python

import asyncio
import copy
import random
import re

import uvloop

from nettacker.core.lib.base import BaseEngine
from nettacker.core.lib.http import send_request, response_conditions_matched
from nettacker.core.utils.common import get_http_header_key, get_http_header_value

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())


class Http_clientEngine(BaseEngine):
    """
    Http_client Engine class to handle HTTP requests with specialized features like safe header dropping.
    """

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
        """
        Run the HTTP client engine for a specific sub-step.

        Args:
            sub_step: The current step configuration from the module YAML.
            module_name: Name of the module.
            target: The target host/URL.
            scan_id: The unique scan identifier.
            options: Scan options.
            process_number: Process ID.
            module_thread_number: Thread number within the module.
            total_module_thread_number: Total threads for the module.
            request_number_counter: Counter for requests.
            total_number_of_requests: Total requests.

        Returns:
            dict: The processing result.
        """
        if options["http_header"] is not None:
            for header in options["http_header"]:
                key = get_http_header_key(header).strip()
                value = get_http_header_value(header)
                if value is not None:
                    sub_step["headers"][key] = value.strip()
                else:
                    sub_step["headers"][key] = ""

        # --- Start of Modification for HttpClientEngine ---
        # Safe Header Dropping: Remove headers that are empty or contain only a prefix (like "Bearer ")
        if "headers" in sub_step:
            headers_to_delete = []
            for header_name, header_value in sub_step["headers"].items():
                # check if header_value is None or Empty String (after stripping)
                if not header_value:
                    headers_to_delete.append(header_name)
                    continue

                if isinstance(header_value, str) and not header_value.strip():
                    headers_to_delete.append(header_name)
                    continue

                # check for incomplete Authorization headers (e.g., "Bearer ", "Token ", "Basic ")
                if (
                    header_name.lower() == "authorization"
                    or header_name.lower() == "proxy-authorization"
                ):
                    # Regex matches a word followed by optional whitespace and end of string
                    # e.g., "Bearer" or "Bearer " matches. "Bearer 123" does not match.
                    if re.match(r"^\w+\s*$", header_value):
                        headers_to_delete.append(header_name)

            for header_name in headers_to_delete:
                del sub_step["headers"][header_name]
        # --- End of Modification ---

        backup_method = copy.deepcopy(sub_step["method"])
        backup_response = copy.deepcopy(sub_step["response"])
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
