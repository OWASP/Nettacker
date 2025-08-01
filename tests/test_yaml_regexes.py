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
    with open(file_path, "r") as f:
        return yaml.safe_load(f)


def extract_http_regexes(payloads):
    regexes = []
    for payload in payloads:
        if payload.get("library") != "http":
            continue
        for step in payload.get("steps", []):
            conditions = step.get("response", {}).get("conditions", {})
            if "content" in conditions and "regex" in conditions["content"]:
                regexes.append(conditions["content"]["regex"])
    return regexes


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
