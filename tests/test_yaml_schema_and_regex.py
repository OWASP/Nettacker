import os
import re

import pytest
import yaml
from schema import Schema, Optional, And, Or

BASE_DIRS = ["nettacker/modules/vuln", "nettacker/modules/scan", "nettacker/modules/brute"]
# Maps request header names to response header names for known reflection patterns
REFLECTED_HEADERS = {"origin": "access-control-allow-origin"}

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


def resolve_input_format(value):
    """Resolve a literal or nettacker_fuzzer header value to a concrete string by substituting
    fuzzer double-brace variables with representative values. Single-brace placeholders like
    {target} are left as-is so they remain valid literals in both the test string and the regex."""
    if isinstance(value, dict) and "nettacker_fuzzer" in value:
        fmt = value["nettacker_fuzzer"]["input_format"]
    else:
        fmt = str(value)
    return (
        fmt.replace("{{schema}}", "http")
        .replace("{{ports}}", "80")
        .replace("{{paths}}", "testpath")
    )


def is_valid_regex(regex: str, header_value: str = None) -> bool:
    """Validate a regex pattern's syntax or verify it matches a specific header value."""
    try:
        pattern = re.compile(regex)
        if header_value is not None:
            return bool(re.search(pattern, header_value))
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
# BRUTE Schema
# ----------------------------

BRUTE_LIBRARIES = {
    "ftp",
    "ftps",
    "pop3",
    "pop3s",
    "smtp",
    "smtps",
    "ssh",
    "telnet",
    "smb",
}

PASSWORD_FUZZER_SCHEMA = Schema(
    {
        "nettacker_fuzzer": {
            "input_format": str,
            "prefix": Or(str, None),
            "suffix": Or(str, None),
            "interceptors": Or(list, None),
            "data": {"passwords": {"read_from_file": str}},
        }
    },
    ignore_extra_keys=False,
)

BRUTE_RESPONSE_SCHEMA = Schema(
    {
        Optional("condition_type"): And(str, lambda s: s.lower() in ["and", "or"]),
        "conditions": {
            "successful_login": {
                "regex": str,
                "reverse": bool,
            }
        },
    },
    ignore_extra_keys=False,
)

BRUTE_STEP_SCHEMA = Schema(
    {
        "method": "brute_force",
        Optional("timeout"): int,
        "host": str,
        "ports": [int],
        Optional("usernames"): list,
        "passwords": PASSWORD_FUZZER_SCHEMA,
        "response": BRUTE_RESPONSE_SCHEMA,
    },
    ignore_extra_keys=False,
)

BRUTE_PAYLOAD_SCHEMA = Schema(
    {
        "library": And(str, lambda s: s in BRUTE_LIBRARIES),
        "steps": [BRUTE_STEP_SCHEMA],
    },
    ignore_extra_keys=False,
)


# ----------------------------
# Validation Logic
# ----------------------------


def extract_brute_regexes(payloads):
    """Validate brute-force payloads against the schema and extract regex patterns."""
    regexes = []

    for payload in payloads:
        BRUTE_PAYLOAD_SCHEMA.validate(payload)

        for step in payload.get("steps", []):
            response = step.get("response", {})
            conditions = response.get("conditions", {})

            if "successful_login" in conditions:
                regex = conditions["successful_login"].get("regex")
                if regex is not None:
                    regexes.append((regex, None))

    return regexes


def validate_http_conditions(conditions: dict):
    """Validate an HTTP conditions block against the schema and extract regex patterns."""
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
                nested_conditions = nested_response["conditions"]
                for field, value in nested_conditions.items():
                    if isinstance(value, dict) and "regex" in value:
                        regexes.append((value["regex"], None))
                    # Headers special structure
                    if field == "headers" and isinstance(value, dict):
                        for header_name, header_block in value.items():
                            if isinstance(header_block, dict) and "regex" in header_block:
                                regexes.append((header_block["regex"], None))

    return regexes


def extract_http_regexes(payloads):
    """Extract regex patterns and their expected header values from HTTP library payloads."""
    regexes = []

    for payload in payloads:
        HTTP_PAYLOAD_SCHEMA.validate(payload)

        for step in payload.get("steps", []):
            response = step.get("response", {})

            if response:
                HTTP_RESPONSE_SCHEMA.validate(response)

            conditions = response.get("conditions", {})
            if not conditions:
                continue

            regexes.extend(validate_http_conditions(conditions))
            raw_headers = step.get("headers", {})
            if isinstance(raw_headers, list):
                request_headers = {k.lower(): v for h in raw_headers for k, v in h.items()}
            else:
                request_headers = {k.lower(): v for k, v in raw_headers.items()}
            for field, value in conditions.items():
                # simple regex fields (status_code, reason, url, content, responsetime)
                if isinstance(value, dict) and "regex" in value:
                    regexes.append((value["regex"], None))
                # headers case
                if field == "headers":
                    for resp_header_name, header_block in value.items():
                        if isinstance(header_block, dict) and "regex" in header_block:
                            header_value = None
                            for req_header, resp_header in REFLECTED_HEADERS.items():
                                if (
                                    resp_header == resp_header_name.lower()
                                    and req_header in request_headers
                                ):
                                    header_value = resolve_input_format(
                                        request_headers[req_header]
                                    )
                                    break
                            regexes.append((header_block["regex"], header_value))

    return regexes


def extract_socket_regexes(payloads):
    """Extract regex patterns from socket library payloads."""
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
                        regexes.append((service_block["regex"], None))

            elif "time_response" in conditions:  # for icmp.yaml
                tr = conditions["time_response"]
                if isinstance(tr, dict) and "regex" in tr:
                    regexes.append((tr["regex"], None))

    return regexes


@pytest.mark.parametrize("yaml_file", list(get_yaml_files()))
def test_yaml_schema_and_regex_valid(yaml_file):
    """Test to validate all YAML module regexes against syntax and header values."""
    data = load_yaml(yaml_file)
    payloads = data.get("payloads", [])

    http_payloads = [p for p in payloads if p.get("library") == "http"]
    socket_payloads = [p for p in payloads if p.get("library") == "socket"]
    brute_payloads = [p for p in payloads if p.get("library") in BRUTE_LIBRARIES]

    if not http_payloads and not socket_payloads and not brute_payloads:
        pytest.skip(
            f"{yaml_file}: no supported payload libraries found (expected http, socket, or brute protocols)"
        )

    regexes = []
    if http_payloads:
        regexes.extend(extract_http_regexes(http_payloads))
    if socket_payloads:
        regexes.extend(extract_socket_regexes(socket_payloads))
    if brute_payloads:
        regexes.extend(extract_brute_regexes(brute_payloads))

    for regex, header_value in regexes:
        assert is_valid_regex(regex, header_value), f"Invalid regex in {yaml_file}: `{regex}`" + (
            f" (must match: {header_value!r})" if header_value else ""
        )
