import copy
import ctypes
import datetime
import hashlib
import importlib
import math
import multiprocessing
import random
import re
import string
import sys
import time
from itertools import product

from nettacker import logger

log = logger.get_logger()


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


def merge_logs_to_list(result, log_list=[]):
    if isinstance(result, dict):
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
    while threads:
        try:
            for thread in threads:
                if not thread.is_alive():
                    threads.remove(thread)
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


def find_args_value(args_name):
    try:
        return sys.argv[sys.argv.index(args_name) + 1]
    except Exception:
        return None


def re_address_repeaters_key_name(key_name):
    return "".join(["['" + _key + "']" for _key in key_name.split("/")[:-1]])


def generate_new_sub_steps(sub_steps, data_matrix, arrays):
    original_sub_steps = copy.deepcopy(sub_steps)
    steps_array = []
    for array in data_matrix:
        array_name_position = 0
        for array_name in arrays:
            for sub_step in sub_steps:
                exec(
                    "original_sub_steps{key_name} = {matrix_value}".format(
                        key_name=re_address_repeaters_key_name(array_name),
                        matrix_value=(
                            '"' + str(array[array_name_position]) + '"'
                            if isinstance(array[array_name_position], int)
                            or isinstance(array[array_name_position], str)
                            else array[array_name_position]
                        ),
                    )
                )
            array_name_position += 1
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
    def apply_data_functions_new():
        if item not in AVAILABLE_DATA_FUNCTIONS:
            return

        for fn_name in data[item]:
            if fn_name in AVAILABLE_DATA_FUNCTIONS[item]:
                fn = getattr(importlib.import_module("nettacker.core.fuzzer"), fn_name)
                if fn is not None:
                    original_data[item] = fn(data[item][fn_name])

    def apply_data_functions_old():
        function_results = {}
        globals().update(locals())
        exec(
            "fuzzer_function = {fuzzer_function}".format(fuzzer_function=data[item]),
            globals(),
            function_results,
        )
        original_data[item] = function_results["fuzzer_function"]

    original_data = copy.deepcopy(data)
    for item in data:
        if isinstance((data[item]), str) and data[item].startswith("fuzzer_function"):
            apply_data_functions_old()
        else:
            apply_data_functions_new()

    return original_data


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
            interceptors_function = ""
            interceptors_function_processed = ""

            if interceptors:
                interceptors_function += "interceptors_function_processed = "
                for interceptor in interceptors[::-1]:
                    interceptors_function += "{interceptor}(".format(interceptor=interceptor)
                interceptors_function += "input_format.format(**formatted_data)" + str(
                    ")" * interceptors_function.count("(")
                )
                expected_variables = {}
                globals().update(locals())
                exec(interceptors_function, globals(), expected_variables)
                interceptors_function_processed = expected_variables[
                    "interceptors_function_processed"
                ]
            else:
                interceptors_function_processed = input_format.format(**formatted_data)

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
