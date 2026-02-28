import os
import re

import pytest
import yaml
from schema import Schema, Optional, And, Or

BASE_DIRS = ["nettacker/modules/vuln", "nettacker/modules/scan"]

# ----------------------------
# Utility
# ----------------------------


def get_yaml_files():
    for base in BASE_DIRS:
        for file in os.listdir(base):
            if file.endswith(".yaml"):
                yield os.path.join(base, file)


def load_yaml(file_path):
    with open(file_path, "r") as f:
        return yaml.safe_load(f)


def is_valid_regex(regex: str) -> bool:
    try:
        re.compile(regex)
        return True
    except re.error:
        return False


# ----------------------------
# HTTP Schema
# ----------------------------

HTTP_CONDITION_SCHEMA = Schema(
    {
        Optional("reason"): dict,
        Optional("status_code"): dict,
        Optional("content"): dict,
        Optional("url"): dict,
        Optional("headers"): dict,
        Optional("responsetime"): Or(str, dict),
        Optional("iterative_response_match"): dict,
    },
    ignore_extra_keys=False,  # reject any other condition field
)

HTTP_RESPONSE_SCHEMA = Schema(
    {
        Optional("condition_type"): And(str, lambda s: s.lower() in ["and", "or"]),
        Optional("conditions"): dict,
        Optional("log"): str,
        Optional("dependent_on_temp_event"): str,
        Optional("save_to_temp_events_only"): str,
        Optional("success_conditions"): object,
    },
    ignore_extra_keys=False,
)

HTTP_STEP_SCHEMA = Schema(
    {
        "method": str,
        "url": object,
        Optional("headers"): Or(dict, [dict]),
        Optional("timeout"): int,
        Optional("allow_redirects"): bool,
        Optional("ssl"): bool,
        Optional("data"): object,
        Optional("json"): object,
        Optional("ports"): object,
        Optional("usernames"): object,
        Optional("passwords"): object,
        Optional("response"): dict,
    },
    ignore_extra_keys=False,
)

HTTP_PAYLOAD_SCHEMA = Schema(
    {
        "library": "http",
        "steps": [HTTP_STEP_SCHEMA],
    },
    ignore_extra_keys=True,
)


# ----------------------------
# SOCKET Schema
# ----------------------------

SOCKET_PAYLOAD_SCHEMA = Schema(
    {
        "library": "socket",
        "steps": list,
    },
    ignore_extra_keys=True,
)


# ----------------------------
# Validation Logic
# ----------------------------


def validate_http_conditions(conditions: dict):
    HTTP_CONDITION_SCHEMA.validate(conditions)
    regexes = []
    # Validate nested iterative_response_match structure
    if "iterative_response_match" in conditions:
        for vendor_name, vendor_block in conditions["iterative_response_match"].items():
            assert (
                "response" in vendor_block
            ), f"Missing 'response' inside iterative_response_match -> {vendor_name}"

            nested_response = vendor_block["response"]

            HTTP_RESPONSE_SCHEMA.validate(nested_response)

            if "conditions" in nested_response:
                HTTP_CONDITION_SCHEMA.validate(nested_response["conditions"])
                if (
                    "content" in nested_response["conditions"]
                    and "regex" in nested_response["conditions"]["content"]
                ):
                    regexes.append(nested_response["conditions"]["content"]["regex"])

    return regexes


def extract_http_regexes(payloads):
    regexes = []

    for payload in payloads:
        HTTP_PAYLOAD_SCHEMA.validate(payload)

        for step in payload.get("steps", []):
            response = step.get("response", {})
            if response:
                HTTP_RESPONSE_SCHEMA.validate(response)

            conditions = response.get("conditions", {})

            if conditions:
                regexes.extend(validate_http_conditions(conditions))
                if "content" in conditions and "regex" in conditions["content"]:
                    regexes.append(conditions["content"]["regex"])

    return regexes


def extract_socket_regexes(payloads):
    regexes = []

    for payload in payloads:
        SOCKET_PAYLOAD_SCHEMA.validate(payload)

        for step in payload.get("steps", []):
            response = step.get("response", {})
            conditions = response.get("conditions", {})

            if "service" in conditions:  # for port.yaml
                services = conditions["service"]
                for service_block in services.values():
                    if isinstance(service_block, dict) and "regex" in service_block:
                        regexes.append(service_block["regex"])

            elif "time_response" in conditions:  # for icmp.yaml
                tr = conditions["time_response"]
                if isinstance(tr, dict) and "regex" in tr:
                    regexes.append(tr["regex"])

    return regexes


@pytest.mark.parametrize("yaml_file", list(get_yaml_files()))
def test_yaml_schema_and_regex_valid(yaml_file):
    data = load_yaml(yaml_file)
    payloads = data.get("payloads", [])

    http_payloads = [p for p in payloads if p.get("library") == "http"]
    socket_payloads = [p for p in payloads if p.get("library") == "socket"]

    if not http_payloads and not socket_payloads:
        pytest.skip(f"No http/socket payloads found in {yaml_file}")

    regexes = []
    if http_payloads:
        regexes.extend(extract_http_regexes(http_payloads))
    if socket_payloads:
        regexes.extend(extract_socket_regexes(socket_payloads))

    for regex in regexes:
        assert is_valid_regex(regex), f"Invalid regex in {yaml_file}: `{regex}`"
