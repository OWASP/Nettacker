#!/usr/bin/env python

import asyncio
import copy
import random
import re
import time
import ssl
from typing import Dict, Any, Optional, Union

import aiohttp
import uvloop
from aiohttp import ClientSession, ClientTimeout

from nettacker.core.lib.base import BaseEngine
from nettacker.core.utils.common import (
    replace_dependent_response,
    reverse_and_regex_condition,
)

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

# Constants for secure defaults
DEFAULT_TIMEOUT = ClientTimeout(total=30)
DEFAULT_HEADERS = {
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'close'
}
MIN_TLS_VERSION = ssl.TLSVersion.TLSv1_2

async def perform_request_action(
    action: callable,
    request_options: Dict[str, Any]
) -> Dict[str, Any]:
    """Perform an HTTP request and return processed response."""
    start_time = time.monotonic()
    try:
        async with action(**request_options) as response:
            content = await response.read()
            try:
                content_str = content.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                content_str = content.decode('latin-1', errors='ignore')
            
            return {
                "reason": str(response.reason),
                "url": str(response.url),
                "status_code": response.status,
                "content": content_str,
                "raw_content": content,
                "headers": {k.lower(): v for k, v in response.headers.items()},
                "responsetime": time.monotonic() - start_time,
                "success": True
            }
    except Exception as e:
        return {
            "error": str(e),
            "responsetime": time.monotonic() - start_time,
            "success": False
        }

async def send_request(
    request_options: Dict[str, Any],
    method: str
) -> Dict[str, Any]:
    """Send an HTTP request with proper SSL and timeout configuration."""
    ssl_context = ssl.create_default_context()
    ssl_context.minimum_version = MIN_TLS_VERSION
    
    # Merge default headers
    headers = request_options.get('headers', {})
    request_options['headers'] = {**DEFAULT_HEADERS, **headers}
    
    # Configure timeout
    request_options.setdefault('timeout', DEFAULT_TIMEOUT)
    
    async with ClientSession(
        connector=aiohttp.TCPConnector(ssl=ssl_context),
        raise_for_status=False
    ) as session:
        action = getattr(session, method.lower(), None)
        if action is None:
            raise ValueError(f"Invalid HTTP method: {method}")
            
        try:
            response = await perform_request_action(action, request_options)
            if not response.get('success', False):
                raise aiohttp.ClientError(response.get('error', 'Unknown error'))
            return response
        except Exception as e:
            return {
                "error": str(e),
                "success": False
            }

def response_conditions_matched(
    sub_step: Dict[str, Any],
    response: Dict[str, Any]
) -> Dict[str, Any]:
    """Check if response matches the defined conditions."""
    if not response or not response.get('success', False):
        return {}

    condition_type = sub_step["response"]["condition_type"].lower()
    conditions = sub_step["response"]["conditions"]
    condition_results = {}

    # Process standard conditions
    for condition in conditions:
        if condition in ["reason", "status_code", "content", "url"]:
            try:
                regex = re.findall(
                    re.compile(conditions[condition]["regex"]),
                    str(response.get(condition, ""))
                )
                condition_results[condition] = reverse_and_regex_condition(
                    regex,
                    conditions[condition]["reverse"]
                )
            except re.error:
                condition_results[condition] = []

        elif condition == "headers":
            condition_results["headers"] = {}
            for header in conditions["headers"]:
                try:
                    header_value = response["headers"].get(header.lower(), "")
                    regex = re.findall(
                        re.compile(conditions["headers"][header]["regex"]),
                        str(header_value)
                    )
                    condition_results["headers"][header] = reverse_and_regex_condition(
                        regex,
                        conditions["headers"][header]["reverse"]
                    )
                except (TypeError, KeyError):
                    condition_results["headers"][header] = []

        elif condition == "responsetime":
            try:
                time_cond = conditions["responsetime"].split()
                if len(time_cond) == 2 and time_cond[0] in ["==", "!=", ">=", "<=", ">", "<"]:
                    op = time_cond[0]
                    threshold = float(time_cond[1])
                    response_time = response["responsetime"]
                    
                    # Safely evaluate the condition
                    condition_met = eval(f"{response_time} {op} {threshold}", {}, {})
                    condition_results["responsetime"] = response_time if condition_met else []
                else:
                    condition_results["responsetime"] = []
            except (ValueError, AttributeError):
                condition_results["responsetime"] = []

    # Process condition type (AND/OR)
    if condition_type == "or":
        if any(
            result != [] 
            for result in condition_results.values() 
            if not isinstance(result, dict)
        ) or (
            "headers" in condition_results 
            and any(result != [] for result in condition_results["headers"].values())
        ):
            return _add_log_to_conditions(sub_step, condition_results)
        return {}

    elif condition_type == "and":
        if not any(
            result == [] 
            for result in condition_results.values() 
            if not isinstance(result, dict)
        ) and (
            "headers" not in condition_results 
            or not any(result == [] for result in condition_results["headers"].values())
        ):
            return _add_log_to_conditions(sub_step, condition_results)
        return {}

    return {}

def _add_log_to_conditions(
    sub_step: Dict[str, Any],
    condition_results: Dict[str, Any]
) -> Dict[str, Any]:
    """Add log information to condition results if configured."""
    if sub_step["response"].get("log", False):
        condition_results["log"] = sub_step["response"]["log"]
        if "response_dependent" in condition_results["log"]:
            condition_results["log"] = replace_dependent_response(
                condition_results["log"],
                condition_results
            )
    return condition_results

class HttpEngine(BaseEngine):
    async def run(
        self,
        sub_step: Dict[str, Any],
        module_name: str,
        target: str,
        scan_id: str,
        options: Dict[str, Any],
        process_number: int,
        module_thread_number: int,
        total_module_thread_number: int,
        request_number_counter: int,
        total_number_of_requests: int,
    ) -> Any:
        """Execute the HTTP request and process results."""
        # Preserve original configuration
        original_config = {
            "method": copy.deepcopy(sub_step["method"]),
            "response": copy.deepcopy(sub_step["response"]),
            "iterative_match": copy.deepcopy(
                sub_step["response"]["conditions"].get("iterative_response_match")
            )
        }

        # Configure request
        if options.get("user_agent") == "random_user_agent":
            sub_step["headers"]["User-Agent"] = random.choice(options["user_agents"])

        # Handle dependencies
        if "dependent_on_temp_event" in original_config["response"]:
            temp_event = self.get_dependent_results_from_database(
                target,
                module_name,
                scan_id,
                original_config["response"]["dependent_on_temp_event"],
            )
            sub_step = self.replace_dependent_values(sub_step, temp_event)

        # Prepare for request
        method = sub_step.pop("method")
        response_config = sub_step.pop("response")

        # Execute request with retries
        response = {}
        for _ in range(options.get("retries", 3)):
            try:
                response = await send_request(sub_step, method)
                if response.get("success", False):
                    response["content"] = response.get("content", "")
                    break
            except Exception as e:
                response = {"error": str(e), "success": False}

        # Restore original configuration
        sub_step["method"] = method
        sub_step["response"] = response_config

        # Process iterative response matching if configured
        iterative_match = None
        if original_config["iterative_match"] is not None:
            iterative_match = sub_step["response"]["conditions"].pop(
                "iterative_response_match",
                None
            )

        # Evaluate response conditions
        sub_step["response"]["conditions_results"] = response_conditions_matched(
            sub_step,
            response
        )

        # Process iterative matches if conditions met
        if iterative_match and (
            sub_step["response"]["conditions_results"]
            or sub_step["response"]["condition_type"].lower() == "or"
        ):
            sub_step["response"]["conditions"]["iterative_response_match"] = iterative_match
            for key in iterative_match:
                result = response_conditions_matched(
                    iterative_match[key],
                    response
                )
                if result:
                    sub_step["response"]["conditions_results"][key] = result

        return await self.process_conditions(
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