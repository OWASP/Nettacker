#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import copy
import os
import socket
import yaml
import time
import json
from glob import glob
from io import StringIO
from nettacker.core.socks_proxy import set_socks_proxy


class NettackerModules:
    def __init__(
        self,
        options,
        module_name,
        scan_unique_id,
        process_number,
        thread_number,
        total_number_threads,
    ):
        from nettacker.config import nettacker_paths

        self.module_name = module_name
        self.process_number = process_number
        self.module_thread_number = thread_number
        self.total_module_thread_number = total_number_threads
        self.module_inputs = vars(options)
        if options.modules_extra_args:
            for module_extra_args in self.module_inputs["modules_extra_args"]:
                self.module_inputs[module_extra_args] = self.module_inputs["modules_extra_args"][
                    module_extra_args
                ]
        self.scan_unique_id = scan_unique_id
        self.target = options.target
        self.skip_service_discovery = options.skip_service_discovery

        self.discovered_services = None
        self.ignored_core_modules = ["subdomain_scan", "icmp_scan", "port_scan"]
        self.service_discovery_signatures = list(
            set(
                yaml.load(
                    StringIO(
                        open(nettacker_paths()["modules_path"] / "scan/port.yaml")
                        .read()
                        .format(**{"target": "dummy"})
                    ),
                    Loader=yaml.FullLoader,
                )["payloads"][0]["steps"][0]["response"]["conditions"].keys()
            )
        )
        self.libraries = [
            module_protocol.split(".py")[0]
            for module_protocol in os.listdir(nettacker_paths()["module_protocols_path"])
            if module_protocol.endswith(".py") and module_protocol != "__init__.py"
        ]

    def load(self):
        from nettacker.config import nettacker_paths
        from nettacker.core.utility import find_and_replace_configuration_keys
        from nettacker.database.db import find_events

        self.module_content = find_and_replace_configuration_keys(
            yaml.load(
                StringIO(
                    open(
                        nettacker_paths()["modules_path"]
                        / self.module_name.split("_")[-1].split(".yaml")[0]
                        / f"{'_'.join(self.module_name.split('_')[:-1])}.yaml",
                        "r",
                    )
                    .read()
                    .format(**self.module_inputs)
                ),
                Loader=yaml.FullLoader,
            ),
            self.module_inputs,
        )
        if not self.skip_service_discovery and self.module_name not in self.ignored_core_modules:
            services = {}
            for service in find_events(self.target, "port_scan", self.scan_unique_id):
                service_event = json.loads(service.json_event)
                port = service_event["ports"]
                protocols = service_event["response"]["conditions_results"].keys()
                for protocol in protocols:
                    if "core_" + protocol in self.libraries and protocol:
                        if protocol in services:
                            services[protocol].append(port)
                        else:
                            services[protocol] = [port]
            self.discovered_services = copy.deepcopy(services)
            index_payload = 0
            for payload in copy.deepcopy(self.module_content["payloads"]):
                if (
                    payload["library"] not in self.discovered_services
                    and payload["library"] in self.service_discovery_signatures
                ):
                    del self.module_content["payloads"][index_payload]
                    index_payload -= 1
                else:
                    index_step = 0
                    for step in copy.deepcopy(
                        self.module_content["payloads"][index_payload]["steps"]
                    ):
                        find_and_replace_configuration_keys(
                            step, {"ports": self.discovered_services[payload["library"]]}
                        )
                        self.module_content["payloads"][index_payload]["steps"][index_step] = step
                        index_step += 1
                index_payload += 1

    def generate_loops(self):
        from nettacker.core.utility import expand_module_steps

        self.module_content["payloads"] = expand_module_steps(self.module_content["payloads"])

    def sort_loops(self):
        steps = []
        for index in range(len(self.module_content["payloads"])):
            for step in copy.deepcopy(self.module_content["payloads"][index]["steps"]):
                if "dependent_on_temp_event" not in step[0]["response"]:
                    steps.append(step)

            for step in copy.deepcopy(self.module_content["payloads"][index]["steps"]):
                if (
                    "dependent_on_temp_event" in step[0]["response"]
                    and "save_to_temp_events_only" in step[0]["response"]
                ):
                    steps.append(step)

            for step in copy.deepcopy(self.module_content["payloads"][index]["steps"]):
                if (
                    "dependent_on_temp_event" in step[0]["response"]
                    and "save_to_temp_events_only" not in step[0]["response"]
                ):
                    steps.append(step)
            self.module_content["payloads"][index]["steps"] = steps

    def start(self):
        from terminable_thread import Thread
        from nettacker.core.utility import wait_for_threads_to_finish

        active_threads = []
        from nettacker.core.alert import warn
        from nettacker.core.alert import verbose_event_info
        from nettacker.core.alert import messages

        # counting total number of requests
        total_number_of_requests = 0
        for payload in self.module_content["payloads"]:
            if "core_" + payload["library"] not in self.libraries:
                warn(messages("library_not_supported").format(payload["library"]))
                return None
            for step in payload["steps"]:
                total_number_of_requests += len(step)
        request_number_counter = 0
        for payload in self.module_content["payloads"]:
            protocol = getattr(
                __import__(
                    "nettacker.core.module_protocols.core_{library}".format(library=payload["library"]),
                    fromlist=["Engine"],
                ),
                "Engine",
            )
            for step in payload["steps"]:
                for sub_step in step:
                    thread = Thread(
                        target=protocol.run,
                        args=(
                            sub_step,
                            self.module_name,
                            self.target,
                            self.scan_unique_id,
                            self.module_inputs,
                            self.process_number,
                            self.module_thread_number,
                            self.total_module_thread_number,
                            request_number_counter,
                            total_number_of_requests,
                        ),
                    )
                    thread.name = f"{self.target} -> {self.module_name} -> {sub_step}"
                    request_number_counter += 1
                    verbose_event_info(
                        messages("sending_module_request").format(
                            self.process_number,
                            self.module_name,
                            self.target,
                            self.module_thread_number,
                            self.total_module_thread_number,
                            request_number_counter,
                            total_number_of_requests,
                        )
                    )
                    thread.start()
                    time.sleep(self.module_inputs["time_sleep_between_requests"])
                    active_threads.append(thread)
                    wait_for_threads_to_finish(
                        active_threads,
                        maximum=self.module_inputs["thread_per_host"],
                        terminable=True,
                    )
        wait_for_threads_to_finish(active_threads, maximum=None, terminable=True)


def load_all_graphs():
    """
    load all available graphs

    Returns:
        an array of graph names
    """
    from nettacker.config import nettacker_paths

    graph_names = []
    for graph_library in nettacker_paths()["graph_path"].glob("*/engine.py"):
        graph_names.append(str(graph_library).split("/")[-2] + "_graph")
    return list(set(graph_names))


def load_all_languages():
    """
    load all available languages

    Returns:
        an array of languages
    """
    languages_list = []
    from nettacker.config import nettacker_paths

    for language in nettacker_paths()["messages_path"].glob("*.yaml"):
        languages_list.append(str(language).split("/")[-1].split(".")[0])
    return list(set(languages_list))


def load_all_modules(limit=-1, full_details=False):
    """
    load all available modules

    limit: return limited number of modules
    full: with full details

    Returns:
        an array of all module names
    """
    # Search for Modules
    from nettacker.config import nettacker_paths
    from nettacker.core.utility import sort_dictionary

    if full_details:
        import yaml
    module_names = {}
    for module_name in nettacker_paths()["modules_path"].glob("*.yaml"):
        libname = module_name.split("/")[-1].split(".")[0]
        category = module_name.split("/")[-2]
        module_names[libname + "_" + category] = (
            yaml.load(
                StringIO(
                    open(
                        nettacker_paths()["modules_path"] / category / f"{libname}.yaml",
                        "r",
                    )
                    .read()
                    .split("payload:")[0]
                ),
                Loader=yaml.FullLoader,
            )["info"]
            if full_details
            else None
        )
        if len(module_names) == limit:
            module_names["..."] = {}
            break
    module_names = sort_dictionary(module_names)
    module_names["all"] = {}

    return module_names


def load_all_profiles(limit=-1):
    """
    load all available profiles

    Returns:
        an array of all profile names
    """
    from nettacker.core.utility import sort_dictionary

    all_modules_with_details = load_all_modules(limit=limit, full_details=True)
    profiles = {}
    if "..." in all_modules_with_details:
        del all_modules_with_details["..."]
    del all_modules_with_details["all"]
    for key in all_modules_with_details:
        for tag in all_modules_with_details[key]["profiles"]:
            if tag not in profiles:
                profiles[tag] = []
                profiles[tag].append(key)
            else:
                profiles[tag].append(key)
            if len(profiles) == limit:
                profiles = sort_dictionary(profiles)
                profiles["..."] = []
                profiles["all"] = []
                return profiles
    profiles = sort_dictionary(profiles)
    profiles["all"] = []
    return profiles


def perform_scan(
    options,
    target,
    module_name,
    scan_unique_id,
    process_number,
    thread_number,
    total_number_threads,
):
    from nettacker.core.alert import verbose_event_info, messages

    socket.socket, socket.getaddrinfo = set_socks_proxy(options.socks_proxy)
    options.target = target

    validate_module = NettackerModules(
        options, module_name, scan_unique_id, process_number, thread_number, total_number_threads
    )
    validate_module.load()
    validate_module.generate_loops()
    validate_module.sort_loops()
    validate_module.start()

    verbose_event_info(
        messages("finished_parallel_module_scan").format(
            process_number, module_name, target, thread_number, total_number_threads
        )
    )
    return os.EX_OK
