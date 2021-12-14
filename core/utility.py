#!/usr/bin/env python
# -*- coding: utf-8 -*-

import copy
import random
import string
import sys
import ctypes
import time
import json
import os
import multiprocessing
import yaml
import hashlib
import re
from core.load_modules import load_all_languages
from core.time import now
from core.color import color


def process_conditions(
        event,
        module_name,
        target,
        scan_unique_id,
        options,
        response,
        process_number,
        module_thread_number,
        total_module_thread_number,
        request_number_counter,
        total_number_of_requests
):
    from core.alert import (success_event_info,
                            verbose_info,
                            messages)

    if 'save_to_temp_events_only' in event.get('response', ''):
        from database.db import submit_temp_logs_to_db
        submit_temp_logs_to_db(
            {
                "date": now(model=None),
                "target": target,
                "module_name": module_name,
                "scan_unique_id": scan_unique_id,
                "event_name": event['response']['save_to_temp_events_only'],
                "port": event.get('ports', ''),
                "event": event,
                "data": response
            }
        )
    if event['response']['conditions_results'] and 'save_to_temp_events_only' not in event.get('response', ''):
        from database.db import submit_logs_to_db

        # remove sensitive information before submitting to db
        from config import nettacker_api_config
        options = copy.deepcopy(options)
        for key in nettacker_api_config():
            try:
                del options[key]
            except Exception:
                continue
        del event['response']['conditions']
        del event['response']['condition_type']
        event_request_keys = copy.deepcopy(event)
        del event_request_keys['response']
        submit_logs_to_db(
            {
                "date": now(model=None),
                "target": target,
                "module_name": module_name,
                "scan_unique_id": scan_unique_id,
                "port": event.get('ports') or event.get('port') or (
                    event.get('url').split(':')[2].split('/')[0] if
                    type(event.get('url')) == str and len(event.get('url').split(':')) >= 3 and
                    event.get('url').split(':')[2].split('/')[0].isdigit() else ""
                ),
                "event": " ".join(
                    yaml.dump(event_request_keys).split()
                ) + " conditions: " + " ".join(
                    yaml.dump(event['response']['conditions_results']).split()
                ),
                "json_event": event
            }
        )
        success_event_info(
            messages("send_success_event_from_module").format(
                process_number,
                module_name,
                target,
                module_thread_number,
                total_module_thread_number,
                request_number_counter,
                total_number_of_requests,
                " ".join(
                    [
                        color('yellow') + key + color('reset') if ':' in key
                        else color('green') + key + color('reset')
                        for key in yaml.dump(event_request_keys).split()
                    ]
                ),
                filter_large_content(
                    "conditions: " + " ".join(
                        [
                            color('purple') + key + color('reset') if ':' in key
                            else color('green') + key + color('reset')
                            for key in yaml.dump(event['response']['conditions_results']).split()
                        ]
                    ),
                    filter_rate=150
                )
            )
        )
        verbose_info(
            json.dumps(event)
        )
        return True
    else:
        del event['response']['conditions']
        verbose_info(
            messages("send_unsuccess_event_from_module").format(
                process_number,
                module_name,
                target,
                module_thread_number,
                total_module_thread_number,
                request_number_counter,
                total_number_of_requests
            )
        )
        verbose_info(
            json.dumps(event)
        )
        return 'save_to_temp_events_only' in event['response']


def filter_large_content(content, filter_rate=150):
    from core.alert import messages
    if len(content) <= filter_rate:
        return content
    else:
        filter_rate -= 1
        filter_index = filter_rate
        for char in content[filter_rate:]:
            if char == ' ':
                return content[0:filter_index] + messages('filtered_content')
            else:
                filter_index += 1
        return content


def get_dependent_results_from_database(target, module_name, scan_unique_id, event_names):
    from database.db import find_temp_events
    events = []
    for event_name in event_names.split(','):
        while True:
            event = find_temp_events(target, module_name, scan_unique_id, event_name)
            if event:
                events.append(json.loads(event.event)['response']['conditions_results'])
                break
            time.sleep(0.1)
    return events


def find_and_replace_dependent_values(sub_step, dependent_on_temp_event):
    if type(sub_step) == dict:
        for key in copy.deepcopy(sub_step):
            if type(sub_step[key]) not in [str, float, int, bytes]:
                sub_step[key] = find_and_replace_dependent_values(
                    copy.deepcopy(sub_step[key]), dependent_on_temp_event
                )
            else:
                if type(sub_step[key]) == str:
                    if 'dependent_on_temp_event' in sub_step[key]:
                        globals().update(locals())
                        generate_new_step = copy.deepcopy(sub_step[key])
                        key_name = re.findall(
                            re.compile("dependent_on_temp_event\\[\\S+\\]\\['\\S+\\]\\[\\S+\\]"),
                            generate_new_step
                        )[0]
                        try:
                            key_value = eval(key_name)
                        except Exception:
                            key_value = "error"
                        sub_step[key] = sub_step[key].replace(key_name, key_value)
    if type(sub_step) == list:
        value_index = 0
        for value in copy.deepcopy(sub_step):
            if type(sub_step[value_index]) not in [str, float, int, bytes]:
                sub_step[key] = find_and_replace_dependent_values(
                    copy.deepcopy(sub_step[value_index]), dependent_on_temp_event
                )
            else:
                if type(sub_step[value_index]) == str:
                    if 'dependent_on_temp_event' in sub_step[value_index]:
                        globals().update(locals())
                        generate_new_step = copy.deepcopy(sub_step[key])
                        key_name = re.findall(
                            re.compile("dependent_on_temp_event\\['\\S+\\]\\[\\S+\\]"),
                            generate_new_step
                        )[0]
                        try:
                            key_value = eval(key_name)
                        except Exception:
                            key_value = "error"
                        sub_step[value_index] = sub_step[value_index].replace(key_name, key_value)
            value_index += 1
    return sub_step


def replace_dependent_values(sub_step, dependent_on_temp_event):
    return find_and_replace_dependent_values(sub_step, dependent_on_temp_event)


def reverse_and_regex_condition(regex, reverse):
    if regex:
        if reverse:
            return []
        return list(set(regex))
    else:
        if reverse:
            return True
        return []


def select_maximum_cpu_core(mode):
    if mode == 'maximum':
        return int(multiprocessing.cpu_count() - 1) if int(multiprocessing.cpu_count() - 1) >= 1 else 1
    elif mode == 'high':
        return int(multiprocessing.cpu_count() / 2) if int(multiprocessing.cpu_count() - 1) >= 1 else 1
    elif mode == 'normal':
        return int(multiprocessing.cpu_count() / 4) if int(multiprocessing.cpu_count() - 1) >= 1 else 1
    elif mode == 'low':
        return int(multiprocessing.cpu_count() / 8) if int(multiprocessing.cpu_count() - 1) >= 1 else 1
    else:
        return 1


def wait_for_threads_to_finish(threads, maximum=None, terminable=False, sub_process=False):
    while threads:
        try:
            dead_threads = []
            for thread in threads:
                if not thread.is_alive():
                    dead_threads.append(thread)
            if dead_threads:
                for thread in dead_threads:
                    threads.remove(thread)
                dead_threads = []
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
    from core.alert import info
    if verbose:
        info("killing {0}".format(thread.name))
    if not thread.is_alive():
        return

    exc = ctypes.py_object(SystemExit)
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(
        ctypes.c_long(thread.ident),
        exc
    )
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


def application_language():
    from config import nettacker_global_config
    nettacker_global_configuration = nettacker_global_config()
    if "-L" in sys.argv:
        language = find_args_value('-L') or 'en'
    elif "--language" in sys.argv:
        language = find_args_value('--language') or 'en'
    else:
        language = nettacker_global_configuration['nettacker_user_application_config']['language']
    if language not in load_all_languages():
        language = 'en'
    return language


def generate_random_token(length=10):
    return "".join(
        random.choice(string.ascii_lowercase) for _ in range(length)
    )


def re_address_repeaters_key_name(key_name):
    return "".join(['[\'' + _key + '\']' for _key in key_name.split('/')[:-1]])


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
                        matrix_value='"' + str(array[array_name_position]) + '"' if type(
                            array[array_name_position]) == int or type(array[array_name_position]) == str else array[
                            array_name_position]
                    )
                )
            array_name_position += 1
        steps_array.append(copy.deepcopy(original_sub_steps))
    return steps_array


def find_repeaters(sub_content, root, arrays):
    if type(sub_content) == dict and 'nettacker_fuzzer' not in sub_content:
        temprory_content = copy.deepcopy(sub_content)
        original_root = root
        for key in sub_content:
            root = original_root
            root += key + '/'
            temprory_content[key], _root, arrays = find_repeaters(sub_content[key], root, arrays)
        sub_content = copy.deepcopy(temprory_content)
        root = original_root
    if (type(sub_content) not in [bool, int, float]) and (
            type(sub_content) == list or 'nettacker_fuzzer' in sub_content):
        arrays[root] = sub_content
    return (sub_content, root, arrays) if root != '' else arrays


def find_and_replace_configuration_keys(module_content, module_inputs):
    if type(module_content) == dict:
        for key in copy.deepcopy(module_content):
            if key in module_inputs:
                if module_inputs[key]:
                    module_content[key] = module_inputs[key]
            elif type(module_content[key]) in [dict, list]:
                module_content[key] = find_and_replace_configuration_keys(module_content[key], module_inputs)
    elif type(module_content) == list:
        array_index = 0
        for key in copy.deepcopy(module_content):
            module_content[array_index] = find_and_replace_configuration_keys(key, module_inputs)
            array_index += 1
    else:
        return module_content
    return module_content


class value_to_class:
    def __init__(self, value):
        self.value = value


def class_to_value(arrays):
    original_arrays = copy.deepcopy(arrays)
    array_index = 0
    for array in arrays:
        value_index = 0
        for value in array:
            if type(value) == value_to_class:
                original_arrays[array_index][value_index] = value.value
            value_index += 1
        array_index += 1
    return original_arrays


def generate_and_replace_md5(content):
    # todo: make it betetr and document it
    md5_content = content.split('NETTACKER_MD5_GENERATOR_START')[1].split('NETTACKER_MD5_GENERATOR_STOP')[0]
    md5_content_backup = md5_content
    if type(md5_content) == str:
        md5_content = md5_content.encode()
    md5_hash = hashlib.md5(md5_content).hexdigest()
    return content.replace(
        'NETTACKER_MD5_GENERATOR_START' + md5_content_backup + 'NETTACKER_MD5_GENERATOR_STOP',
        md5_hash
    )


def arrays_to_matrix(arrays):
    import numpy
    return numpy.array(
        numpy.meshgrid(*[
            arrays[array_name] for array_name in arrays
        ])
    ).T.reshape(
        -1,
        len(arrays.keys())
    ).tolist()


def string_to_bytes(string):
    return string.encode()


def fuzzer_function_read_file_as_array(filename):
    from config import nettacker_paths
    return open(
        os.path.join(
            nettacker_paths()['payloads_path'],
            filename
        )
    ).read().split('\n')


def apply_data_functions(data):
    original_data = copy.deepcopy(data)
    function_results = {}
    globals().update(locals())
    for data_name in data:
        if type(data[data_name]) == str and data[data_name].startswith('fuzzer_function'):
            exec(
                "fuzzer_function = {fuzzer_function}".format(
                    fuzzer_function=data[data_name]
                ),
                globals(),
                function_results
            )
            original_data[data_name] = function_results['fuzzer_function']
    return original_data


def nettacker_fuzzer_repeater_perform(arrays):
    original_arrays = copy.deepcopy(arrays)
    for array_name in arrays:
        if 'nettacker_fuzzer' in arrays[array_name]:
            data = arrays[array_name]['nettacker_fuzzer']['data']
            data_matrix = arrays_to_matrix(apply_data_functions(data))
            prefix = arrays[array_name]['nettacker_fuzzer']['prefix']
            input_format = arrays[array_name]['nettacker_fuzzer']['input_format']
            interceptors = copy.deepcopy(arrays[array_name]['nettacker_fuzzer']['interceptors'])
            if interceptors:
                interceptors = interceptors.split(',')
            suffix = arrays[array_name]['nettacker_fuzzer']['suffix']
            processed_array = []
            for sub_data in data_matrix:
                formatted_data = {}
                index_input = 0
                for value in sub_data:
                    formatted_data[list(data.keys())[index_input]] = value
                    index_input += 1
                interceptors_function = ''
                interceptors_function_processed = ''
                if interceptors:
                    interceptors_function += 'interceptors_function_processed = '
                    for interceptor in interceptors[::-1]:
                        interceptors_function += '{interceptor}('.format(interceptor=interceptor)
                    interceptors_function += 'input_format.format(**formatted_data)' + str(
                        ')' * interceptors_function.count('('))
                    expected_variables = {}
                    globals().update(locals())
                    exec(interceptors_function, globals(), expected_variables)
                    interceptors_function_processed = expected_variables['interceptors_function_processed']
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
    original_content = copy.deepcopy(content)
    for protocol_lib in content:
        for sub_step in content[content.index(protocol_lib)]['steps']:
            arrays = nettacker_fuzzer_repeater_perform(find_repeaters(sub_step, '', {}))
            if arrays:
                original_content[content.index(protocol_lib)]['steps'][
                    original_content[content.index(protocol_lib)]['steps'].index(sub_step)
                ] = generate_new_sub_steps(sub_step, class_to_value(arrays_to_matrix(arrays)), arrays)
            else:
                original_content[content.index(protocol_lib)]['steps'][
                    original_content[content.index(protocol_lib)]['steps'].index(sub_step)
                ] = [  # minimum 1 step in array
                    original_content[content.index(protocol_lib)]['steps'][
                        original_content[content.index(protocol_lib)]['steps'].index(sub_step)
                    ]
                ]
    return original_content


def sort_dictonary(dictionary):
    etc_flag = '...' in dictionary
    if etc_flag:
        del dictionary['...']
    sorted_dictionary = {}
    for key in sorted(dictionary):
        sorted_dictionary[key] = dictionary[key]
    if etc_flag:
        sorted_dictionary['...'] = {}
    return sorted_dictionary
