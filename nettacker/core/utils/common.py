import copy
import ctypes
import datetime
import difflib
import hashlib
import importlib
import json
import math
import multiprocessing
import os
import random
import re
import string
import subprocess
import sys
import time
from itertools import product

from nettacker import logger

log = logger.get_logger()

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_DIR = os.path.join(CURRENT_DIR, "mapping_files")
DEFAULT_SCRIPT_PATH = os.path.join(CURRENT_DIR, "cve_mapper.py")


# In-memory cache for product metadata index
_PRODUCT_INDEX_CACHE = {}

# Common generic words to ignore during single-token overlap matching
GENERIC_WORDS = {
    "server",
    "db",
    "core",
    "plugin",
    "system",
    "app",
    "service",
    "daemon",
    "http",
    "httpd",
}


def tokenize(text: str) -> set:
    """
    Strips non-alphanumeric characters and breaks text into a set of normalized tokens.
    Example: 'Apache httpd v2.4' -> {'apache', 'httpd', 'v2', '4'}
    """
    if not text:
        return set()
    cleaned = re.sub(r"[^a-zA-Z0-9\s]", " ", str(text))
    return set(cleaned.lower().split())


def build_product_index(db_dir: str = DEFAULT_DB_DIR) -> dict:
    """
    Scans mapping_files once and builds a dictionary mapping candidate
    strings (filenames, display_names, PURL names) to actual DB file keys.
    """
    global _PRODUCT_INDEX_CACHE
    if _PRODUCT_INDEX_CACHE:
        return _PRODUCT_INDEX_CACHE

    index = {}
    if not os.path.exists(db_dir):
        return index

    for filename in os.listdir(db_dir):
        if not filename.endswith(".json") or filename.startswith("."):
            continue

        db_key = filename[:-5]  # e.g., 'apache_http_server'
        file_path = os.path.join(db_dir, filename)

        # 1. Map filename variants (underscores and hyphens)
        index[db_key.lower()] = db_key
        index[db_key.replace("_", " ").lower()] = db_key
        index[db_key.replace("_", "-").lower()] = db_key

        # 2. Inspect inner JSON for display_name and purl metadata
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

                # Index display_name (e.g., 'Apache httpd')
                display_name = data.get("display_name")
                if display_name:
                    index[display_name.strip().lower()] = db_key

                # Index PURL package name (e.g., 'pkg:generic/apache-http-server' -> 'apache-http-server')
                purl = data.get("purl", "")
                if "/" in purl:
                    purl_pkg = purl.split("/")[-1].lower()
                    index[purl_pkg] = db_key
                    index[purl_pkg.replace("-", "_")] = db_key
                    index[purl_pkg.replace("-", " ")] = db_key
        except Exception:
            continue

    _PRODUCT_INDEX_CACHE = index
    return index


def resolve_product_key(cpe_service: str, product_name: str, db_dir: str = DEFAULT_DB_DIR) -> str:
    """
    Multi-tiered resolution strategy:
    1. Parse CPE string vendor:product
    2. Exact alias/display_name/PURL match
    3. Token overlap matching
    4. Fuzzy sequence similarity matching (difflib)
    """
    index = build_product_index(db_dir)

    # --- Tier 1: Try CPE resolution first ---
    if cpe_service:
        parts = str(cpe_service).split(":")
        if len(parts) >= 2:
            vendor = parts[0].strip().lower()
            prod = parts[1].strip().lower()

            cpe_candidates = [
                f"{vendor}_{prod}",
                f"{vendor}-{prod}",
                f"{vendor} {prod}",
                prod,
                f"openprinting_{prod}_stack",
            ]

            for cand in cpe_candidates:
                if cand in index:
                    log.info(f"[CVE Lookup] Matched CPE '{cpe_service}' -> DB Key '{index[cand]}'")
                    return index[cand]

    # If no CPE, use product_name
    input_str = product_name or cpe_service or ""
    if not input_str:
        return ""

    clean_input = input_str.strip().lower()

    # --- Tier 2: Direct lookup in dynamic index ---
    if clean_input in index:
        return index[clean_input]

    normalized = re.sub(r"[\s\-]+", "_", clean_input)
    if normalized in index:
        return index[normalized]

    # --- Tier 3: Token Overlap Matching ---
    input_tokens = tokenize(input_str)
    best_match_key = None
    max_token_overlap = 0

    for candidate_alias, db_key in index.items():
        candidate_tokens = tokenize(candidate_alias)
        common_tokens = input_tokens.intersection(candidate_tokens)

        # Filter out generic filler words unless they are the only token
        non_generic_common = {t for t in common_tokens if t not in GENERIC_WORDS}
        overlap_score = len(non_generic_common)

        if overlap_score > max_token_overlap:
            max_token_overlap = overlap_score
            best_match_key = db_key

    if best_match_key and max_token_overlap >= 1:
        log.info(f"[CVE Lookup] Token matched '{input_str}' -> DB Key '{best_match_key}'")
        return best_match_key

    # --- Tier 4: Fuzzy String Similarity Ratio ---
    clean_token_str = " ".join(sorted(input_tokens))
    best_ratio = 0.0
    fuzzy_match_key = None

    for candidate_alias, db_key in index.items():
        candidate_str = " ".join(sorted(tokenize(candidate_alias)))
        ratio = difflib.SequenceMatcher(None, clean_token_str, candidate_str).ratio()

        if ratio > best_ratio and ratio >= 0.65:  # 65% similarity threshold
            best_ratio = ratio
            fuzzy_match_key = db_key

    if fuzzy_match_key:
        log.info(
            f"[CVE Lookup] Fuzzy matched '{input_str}' ({best_ratio:.2f}) -> DB Key '{fuzzy_match_key}'"
        )
        return fuzzy_match_key

    # Fallback to simple normalized string
    return normalized


def get_cves_for_product_version(
    cpe_service: str,
    product: str,
    version: str,
    script_path: str = DEFAULT_SCRIPT_PATH,
    db_dir: str = DEFAULT_DB_DIR,
) -> list:
    """
    Main lookup function: Resolves product name via CPE/Fuzzy index and queries cve_mapper.py.
    """
    if not (cpe_service or product) or not version:
        return []

    # 1. Resolve product key dynamically
    resolved_product = resolve_product_key(cpe_service, product, db_dir)
    if not resolved_product:
        return []

    # 2. Clean and sanitize version (e.g., "9.6.0 or later" -> "9.6.0")
    clean_version = re.split(r"\s+or\s+|\s+", str(version).strip())[0]

    # 3. Path verifications
    if not os.path.exists(script_path):
        log.error(f"[CVE Lookup] Script not found at path: {script_path}")
        return []

    if not os.path.exists(db_dir):
        log.error(f"[CVE Lookup] Database directory not found: {db_dir}")
        return []

    # 4. Construct Subprocess CLI Command
    cmd = [
        "python3",
        script_path,
        "query",
        "--product",
        resolved_product,
        "--version",
        clean_version,
        "--db-dir",
        db_dir,
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)

        if result.returncode == 0 and result.stdout:
            cves = [line.strip() for line in result.stdout.splitlines() if "CVE-" in line.upper()]
            return cves
        else:
            log.info(f"[CVE Lookup] No results found for {resolved_product} {clean_version}")
            return []

    except subprocess.TimeoutExpired:
        log.warn(
            f"[CVE Lookup] Timeout while querying CVEs for {resolved_product} {clean_version}"
        )
        return []
    except Exception as e:
        log.error(f"[CVE Lookup] Failed to execute mapper script: {e}")
        return []


def extract_cpe_and_version(log_item: str):
    """
    Extracts 'cpe_service', 'product', and 'version' (or 'version_template')
    from a formatted Nettacker log string.
    """
    cpe_service, product, version = None, None, None

    if not log_item:
        return cpe_service, product, version

    # 1. Matches "cpe_service: vendor:product:version"
    cpe_match = re.search(
        r"['\"]?cpe_service['\"]?\s*:\s*['\"]?([^'\"]+)['\"]?", log_item, re.IGNORECASE
    )
    if cpe_match:
        cpe_service = cpe_match.group(1).strip()

    # 2. Matches "product: <name>"
    prod_match = re.search(
        r"['\"]?product['\"]?\s*:\s*['\"]?([^'\",]+)['\"]?", log_item, re.IGNORECASE
    )
    if prod_match:
        product = prod_match.group(1).strip()

    # 3. Matches "version_template: <ver>" or "version: <ver>"
    ver_match = re.search(
        r"['\"]?version(?:_template)?['\"]?\s*:\s*['\"]?([^'\",]+)['\"]?", log_item, re.IGNORECASE
    )
    if ver_match:
        version = ver_match.group(1).strip()

    return cpe_service, product, version


def replace_dependent_response(log, response_dependent):
    """The `response_dependent` is needed for `eval` below."""
    if str(log):
        key_name = re.findall(re.compile("response_dependent\\['\\S+\\]"), log)
        for i in key_name:
            try:
                key_value = eval(i)
            except Exception:
                key_value = "response dependent error"
            log = log.replace(i, " ".join(key_value))
        return log


def merge_logs_to_list(result, log_list=None):
    """Recursively extract all 'log' values from a nested dict into a flat deduplicated list.

    Args:
        result: A dict (possibly nested) containing 'log' keys to extract.
        log_list: Accumulator list for recursive calls. Defaults to a new empty list
            on each top-level call to avoid mutable default argument pitfalls.

    Returns:
        A deduplicated list of extracted log values.
    """
    if log_list is None:
        log_list = []
    if isinstance(result, dict):
        if "json_event" in list(result.keys()):
            if not isinstance(result["json_event"], dict):
                result["json_event"] = json.loads(result["json_event"])
        for i in result:
            if "log" == i:
                log_list.append(result["log"])
            else:
                merge_logs_to_list(result[i], log_list)
    return list(set(log_list))


def reverse_and_regex_condition(regex, reverse):
    if regex:
        if reverse:
            return []
        return list(set(regex))
    else:
        if reverse:
            return True
        return []


def wait_for_threads_to_finish(threads, maximum=None, terminable=False, sub_process=False):
    """Wait until all threads finish or the count drops below maximum.

    Args:
        threads: List of Thread (or Process) objects to monitor. Dead entries
            are removed in-place each iteration.
        maximum: If set, return early once fewer than *maximum* threads remain.
        terminable: If True, forcibly terminate surviving threads on KeyboardInterrupt.
        sub_process: If True, kill surviving sub-processes on KeyboardInterrupt.

    Returns:
        True when all threads completed (or fell below *maximum*),
        False if interrupted by KeyboardInterrupt.
    """
    while threads:
        try:
            threads[:] = [t for t in threads if t.is_alive()]
            if maximum and len(threads) < maximum:
                break
            time.sleep(0.01)
        except KeyboardInterrupt:
            if terminable:
                for thread in threads:
                    terminate_thread(thread)
            if sub_process:
                for thread in threads:
                    thread.kill()
            return False
    return True


def terminate_thread(thread, verbose=True):
    """
    kill a thread https://stackoverflow.com/a/15274929
    Args:
        thread: an alive thread
        verbose: verbose mode/boolean
    Returns:
        True/None
    """

    if verbose:
        log.info("killing {0}".format(thread.name))
    if not thread.is_alive():
        return

    exc = ctypes.py_object(SystemExit)
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(thread.ident), exc)
    if res == 0:
        raise ValueError("nonexistent thread id")
    elif res > 1:
        # if it returns a number greater than one, you're in trouble,
        # and you should call it again with exc=NULL to revert the effect
        ctypes.pythonapi.PyThreadState_SetAsyncExc(thread.ident, None)
        raise SystemError("PyThreadState_SetAsyncExc failed")
    return True


def get_http_header_key(http_header):
    """
    Return the HTTP header key based on the full string entered by the user
    Args:
        http_header: a string entered by the user following the -H flag
    Returns:
        1. The HTTP header key if http_header is a key-value pair
        2. The http_header itself if http_header is NOT a key_value pair (i.e. http_header is a plain string)
        3. An empty string if http_header is empty
    Example:
        http_header: "Authorization: Bearer abcdefgh"
        Returns -> "Authorization"
    """
    # Split only at the first ":"
    return http_header.split(":", 1)[0].strip()


def get_http_header_value(http_header):
    """
    Return the HTTP header value based on the full string entered by the user
    Args:
        http_header: a string entered by the user following the -H flag
    Returns:
        1. The HTTP header value if http_header is a key-value pair
        2. None if the http_header is empty or NOT a key-value pair
    Example:
        http_header: "Authorization: Bearer abcdefgh"
        Returns -> "Bearer abcdefgh"
    """
    if not http_header or ":" not in http_header:
        return None
    # Split only at the first ":"
    value = http_header.split(":", 1)[1].strip()
    return value if value else None


def remove_sensitive_header_keys(event):
    """
    Removes the sensitive headers that the user might add
    Args:
        event: The json event which contains the headers
    Returns:
        event: The json event without the sensitive headers
    """
    from nettacker.config import sensitive_headers

    if not isinstance(event, dict):
        return event

    if "headers" in event:
        if not isinstance(event["headers"], dict):
            return event
        for key in list(event["headers"].keys()):
            if key.lower() in sensitive_headers:
                del event["headers"][key]

    return event


def find_args_value(args_name):
    try:
        return sys.argv[sys.argv.index(args_name) + 1]
    except Exception:
        return None


def set_nested_value(d, key_path, value):
    keys = [k for k in key_path.split("/") if k]
    for key in keys[:-1]:
        d = d[key]
    d[keys[-1]] = value


def generate_new_sub_steps(sub_steps, data_matrix, arrays):
    original_sub_steps = copy.deepcopy(sub_steps)
    steps_array = []
    array_names = list(arrays.keys())
    for array in data_matrix:
        for i, array_name in enumerate(array_names):
            set_nested_value(original_sub_steps, array_name, array[i])
        steps_array.append(copy.deepcopy(original_sub_steps))
    return steps_array


def find_repeaters(sub_content, root, arrays):
    if isinstance(sub_content, dict) and "nettacker_fuzzer" not in sub_content:
        temporary_content = copy.deepcopy(sub_content)
        original_root = root
        for key in sub_content:
            root = original_root
            root += key + "/"
            temporary_content[key], _root, arrays = find_repeaters(sub_content[key], root, arrays)
        sub_content = copy.deepcopy(temporary_content)
        root = original_root
    if (not isinstance(sub_content, (bool, int, float))) and (
        isinstance(sub_content, list) or "nettacker_fuzzer" in sub_content
    ):
        arrays[root] = sub_content

    return (sub_content, root, arrays) if root != "" else arrays


class value_to_class:
    def __init__(self, value):
        self.value = value


def class_to_value(arrays):
    original_arrays = copy.deepcopy(arrays)
    array_index = 0
    for array in arrays:
        value_index = 0
        for value in array:
            if isinstance(value, value_to_class):
                original_arrays[array_index][value_index] = value.value
            value_index += 1
        array_index += 1
    return original_arrays


def generate_and_replace_md5(content):
    # todo: make it betetr and document it
    md5_content = content.split("NETTACKER_MD5_GENERATOR_START")[1].split(
        "NETTACKER_MD5_GENERATOR_STOP"
    )[0]
    md5_content_backup = md5_content
    if isinstance(md5_content, str):
        md5_content = md5_content.encode()
    md5_hash = hashlib.md5(md5_content).hexdigest()
    return content.replace(
        "NETTACKER_MD5_GENERATOR_START" + md5_content_backup + "NETTACKER_MD5_GENERATOR_STOP",
        md5_hash,
    )


def generate_target_groups(targets, set_hardware_usage):
    """
    Split a list of targets into smaller sublists based on a specified size.
    """
    if not targets:
        return targets

    targets_total = len(targets)
    split_size = min(set_hardware_usage, targets_total)

    # Calculate the size of each chunk.
    chunk_size = (targets_total + split_size - 1) // split_size

    return [targets[i : i + chunk_size] for i in range(0, targets_total, chunk_size)]


def arrays_to_matrix(arrays):
    """
    Generate a Cartesian product of input arrays as a list of lists.
    """
    return [list(item) for item in product(*[arrays[array_name] for array_name in arrays])]


def string_to_bytes(string):
    return string.encode()


AVAILABLE_DATA_FUNCTIONS = {
    "passwords": {"read_from_file"},
    "paths": {"read_from_file"},
    "urls": {"read_from_file"},
}


def fuzzer_function_read_file_as_array(filename):
    from nettacker.config import PathConfig

    return open(PathConfig().payloads_dir / filename).read().split("\n")


def apply_data_functions(data):
    original_data = copy.deepcopy(data)
    for item in data:
        if item not in AVAILABLE_DATA_FUNCTIONS:
            continue

        for fn_name in data[item]:
            if fn_name in AVAILABLE_DATA_FUNCTIONS[item]:
                fn = getattr(importlib.import_module("nettacker.core.fuzzer"), fn_name)
                if fn is not None:
                    original_data[item] = fn(data[item][fn_name])

    return original_data


ALLOWED_INTERCEPTORS = {
    "generate_and_replace_md5": generate_and_replace_md5,
}


def fuzzer_repeater_perform(arrays):
    original_arrays = copy.deepcopy(arrays)
    for array_name in arrays:
        if "nettacker_fuzzer" not in arrays[array_name]:
            continue

        data = arrays[array_name]["nettacker_fuzzer"]["data"]
        data_matrix = arrays_to_matrix(apply_data_functions(data))
        prefix = arrays[array_name]["nettacker_fuzzer"]["prefix"]
        input_format = arrays[array_name]["nettacker_fuzzer"]["input_format"]
        interceptors = copy.deepcopy(arrays[array_name]["nettacker_fuzzer"]["interceptors"])
        if interceptors:
            interceptors = interceptors.split(",")
        suffix = arrays[array_name]["nettacker_fuzzer"]["suffix"]
        processed_array = []

        for sub_data in data_matrix:
            formatted_data = {}
            index_input = 0
            for value in sub_data:
                formatted_data[list(data.keys())[index_input]] = value
                index_input += 1

            interceptors_function_processed = input_format.format(**formatted_data)

            if interceptors:
                for interceptor in interceptors:
                    if interceptor not in ALLOWED_INTERCEPTORS:
                        raise ValueError(f"Interceptor '{interceptor}' is not allowed")
                    interceptors_function_processed = ALLOWED_INTERCEPTORS[interceptor](
                        interceptors_function_processed
                    )

            processed_sub_data = interceptors_function_processed
            if prefix:
                processed_sub_data = prefix + processed_sub_data
            if suffix:
                processed_sub_data = processed_sub_data + suffix
            processed_array.append(copy.deepcopy(processed_sub_data))
        original_arrays[array_name] = processed_array

    return original_arrays


def expand_module_steps(content):
    return [expand_protocol(x) for x in copy.deepcopy(content)]


def expand_protocol(protocol):
    protocol["steps"] = [expand_step(x) for x in protocol["steps"]]
    return protocol


def expand_step(step):
    arrays = fuzzer_repeater_perform(find_repeaters(step, "", {}))
    if arrays:
        return generate_new_sub_steps(step, class_to_value(arrays_to_matrix(arrays)), arrays)
    else:
        # Minimum 1 step in array
        return [step]


def generate_random_token(length=10):
    return "".join(random.choice(string.ascii_lowercase) for _ in range(length))


def now(format="%Y-%m-%d %H:%M:%S"):
    """
    get now date and time
    Args:
        format: the date and time model, default is "%Y-%m-%d %H:%M:%S"

    Returns:
        the date and time of now
    """
    return datetime.datetime.now().strftime(format)


def select_maximum_cpu_core(mode):
    cpu_count = multiprocessing.cpu_count()

    if cpu_count - 1 == 0:
        return 1

    mode_core_mapping = {
        "maximum": cpu_count - 1,
        "high": cpu_count / 2,
        "normal": cpu_count / 4,
        "low": cpu_count / 8,
    }
    rounded = math.ceil if mode == "high" else math.floor

    return int(max((rounded(mode_core_mapping.get(mode, 1)), 1)))


def sort_dictionary(dictionary):
    etc_flag = "..." in dictionary
    if etc_flag:
        del dictionary["..."]
    sorted_dictionary = {}
    for key in sorted(dictionary):
        sorted_dictionary[key] = dictionary[key]
    if etc_flag:
        sorted_dictionary["..."] = {}
    return sorted_dictionary


def sanitize_path(path):
    """
    Sanitize the file path to preven unathorized access
    Args:
        path: filepath(user input)

    Returns:
        sanitized_path
    """
    return "_".join(
        [
            component
            for component in re.split(r"[/\\]", path)
            if re.match(r"^[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)?$", component)
        ]
    )


def generate_compare_filepath(scan_id):
    return "/report_compare_{date_time}_{scan_id}.json".format(
        date_time=now(format="%Y_%m_%d_%H_%M_%S"),
        scan_id=scan_id,
    )
