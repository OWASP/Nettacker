import os
import re

import pytest
import yaml

BASE_DIRS = ["nettacker/modules/vuln", "nettacker/modules/scan"]
DUMMY_TEST_STRING = (
    "This is a random string for testing regex 220-You are user number HTTP/1.1 200 OK"
)


def get_yaml_files():
    """Yield all YAML file paths found in specific directories."""
    for base in BASE_DIRS:
        for file in os.listdir(base):
            if file.endswith(".yaml"):
                yield os.path.join(base, file)


def load_yaml(file_path):
    """Load and parse a YAML file from the given file path."""
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


def extract_http_regexes(payloads):
    """Extract regex patterns and their expected header values from HTTP library payloads."""
    regexes = []
    # Map request header names to response header names for known reflection patterns
    REFLECTED_HEADERS = {"origin": "access-control-allow-origin"}

    for payload in payloads:
        if payload.get("library") != "http":
            continue
        for step in payload.get("steps", []):
            conditions = step.get("response", {}).get("conditions", {})

            if "content" in conditions and "regex" in conditions["content"]:
                regexes.append((conditions["content"]["regex"], None))

            # Header regex with reflection check
            if "headers" in conditions:
                request_headers = {k.lower(): v for k, v in step.get("headers", {}).items()}

                for resp_header_name, header_conditions in conditions["headers"].items():
                    if not isinstance(header_conditions, dict) or "regex" not in header_conditions:
                        continue

                    header_value = None
                    for req_header, resp_header in REFLECTED_HEADERS.items():
                        if (
                            resp_header == resp_header_name.lower()
                            and req_header in request_headers
                        ):
                            header_value = resolve_input_format(request_headers[req_header])
                            break

                    regexes.append((header_conditions["regex"], header_value))
    return regexes


def extract_socket_regexes(file_name, payloads):
    """Extract regex patterns from socket library payloads."""
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


def is_valid_regex(regex: str, header_value: str = None) -> bool:
    """Validate a regex pattern's syntax or verify it matches a specific header value."""
    try:
        pattern = re.compile(regex)
        if header_value is not None:
            # Compare the regex against the header value
            return bool(re.search(pattern, header_value))
        re.findall(pattern, DUMMY_TEST_STRING)
        return True
    except Exception:
        return False


@pytest.mark.parametrize("yaml_file", list(get_yaml_files()))
def test_yaml_regexes_valid(yaml_file):
    """Test to validate all YAML module regexes against syntax and header values."""
    data = load_yaml(yaml_file)
    payloads = data.get("payloads", [])

    if not payloads:
        pytest.skip(f"No payloads found in {yaml_file}")

    if payloads[0].get("library") == "http":
        regex_pairs = extract_http_regexes(payloads)
    elif payloads[0].get("library") == "socket":
        file_name = os.path.basename(yaml_file)
        regex_pairs = [(r, None) for r in extract_socket_regexes(file_name, payloads)]
    else:
        pytest.skip(f"Unknown library type in {yaml_file}")
        return

    for regex, header_value in regex_pairs:
        assert is_valid_regex(regex, header_value), f"Invalid regex in {yaml_file}: `{regex}`" + (
            f" (must match: {header_value!r})" if header_value else ""
        )
