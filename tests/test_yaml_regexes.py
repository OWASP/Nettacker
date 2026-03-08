import os
import re

import pytest
import yaml

BASE_DIRS = ["nettacker/modules/vuln", "nettacker/modules/scan"]
DUMMY_TEST_STRING = (
    "This is a random string for testing regex 220-You are user number HTTP/1.1 200 OK"
)


def get_yaml_files():
    for base in BASE_DIRS:
        for file in os.listdir(base):
            if file.endswith(".yaml"):
                yield os.path.join(base, file)


def load_yaml(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def extract_http_regexes(payloads):
    regexes = []
    for payload in payloads:
        if payload.get("library") != "http":
            continue
        for step in payload.get("steps", []):
            response = step.get("response", {})
            regexes.extend(extract_regex_values(response))
    return regexes


def extract_regex_values(response):
    def _collect(node):
        regexes = []
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "regex" and isinstance(value, str):
                    regexes.append(value)
                else:
                    regexes.extend(_collect(value))
        elif isinstance(node, list):
            for item in node:
                regexes.extend(_collect(item))
        return regexes

    return _collect(response.get("conditions", {}))


def extract_socket_regexes(file_name, payloads):
    regexes = []

    for payload in payloads:
        if payload.get("library") != "socket":
            continue
        for step in payload.get("steps", []):
            conditions = step.get("response", {}).get("conditions", {})

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


def is_valid_regex(regex: str) -> bool:
    try:
        pattern = re.compile(regex)
        re.findall(pattern, DUMMY_TEST_STRING)
        return True
    except Exception:
        return False


@pytest.mark.parametrize("yaml_file", list(get_yaml_files()))
def test_yaml_regexes_valid(yaml_file):
    data = load_yaml(yaml_file)
    payloads = data.get("payloads", [])

    if not payloads:
        pytest.skip(f"No payloads found in {yaml_file}")

    if payloads[0].get("library") == "http":
        regexes = extract_http_regexes(payloads)
    elif payloads[0].get("library") == "socket":
        file_name = os.path.basename(yaml_file)
        regexes = extract_socket_regexes(file_name, payloads)
    else:
        pytest.skip(f"Unknown library type in {yaml_file}")
        return

    for regex in regexes:
        assert is_valid_regex(regex), f"Invalid regex in {yaml_file}: `{regex}`"


def test_http_cors_reflected_origin_regex_matches_expected_origin():
    data = load_yaml("nettacker/modules/vuln/http_cors.yaml")
    payloads = data.get("payloads", [])

    origins = ("http://evil.com", "https://evil.com")
    matching_regexes = []

    for regex in extract_http_regexes(payloads):
        compiled_regex = re.compile(regex)
        if all(compiled_regex.fullmatch(origin) for origin in origins):
            matching_regexes.append(regex)

    assert matching_regexes, (
        "Expected at least one http_cors regex to fully match both reflected origins: "
        "`http://evil.com` and `https://evil.com`"
    )
