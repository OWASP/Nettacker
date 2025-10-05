import copy
import importlib
import json
import os
import time
from threading import Thread

from nettacker import logger
from nettacker.config import Config
from nettacker.core import queue_manager
from nettacker.core.messages import messages as _
from nettacker.core.template import TemplateLoader
from nettacker.core.utils.common import expand_module_steps, wait_for_threads_to_finish
from nettacker.database.db import find_events

log = logger.get_logger()


class Module:
    def __init__(
        self,
        module_name,
        options,
        target,
        scan_id,
        process_number,
        thread_number,
        total_number_threads,
    ):
        self.module_name = module_name
        self.process_number = process_number
        self.module_thread_number = thread_number
        self.total_module_thread_number = total_number_threads

        self.module_inputs = options.__dict__
        self.module_inputs["target"] = target

        if options.modules_extra_args:
            for module_extra_args in self.module_inputs["modules_extra_args"]:
                self.module_inputs[module_extra_args] = self.module_inputs["modules_extra_args"][
                    module_extra_args
                ]
        self.target = target

        self.scan_id = scan_id
        self.skip_service_discovery = options.skip_service_discovery

        self.discovered_services = None
        self.ignored_core_modules = [
            "subdomain_scan",
            "icmp_scan",
            "port_scan",
            "ssl_weak_version_vuln",
            "ssl_weak_cipher_vuln",
            "ssl_certificate_weak_signature_vuln",
            "ssl_self_signed_certificate_vuln",
            "ssl_expired_certificate_vuln",
            "ssl_expiring_certificate_scan",
        ]

        contents = TemplateLoader("port_scan", {"target": ""}).load()
        self.service_discovery_signatures = list(
            set(
                contents["payloads"][0]["steps"][0]["response"]["conditions"]
                .get("service", set(contents["payloads"][0]["steps"][0]["response"]["conditions"]))
                .keys()
            )
        )

        self.libraries = [
            module_protocol.split(".py")[0]
            for module_protocol in os.listdir(Config.path.module_protocols_dir)
            if module_protocol.endswith(".py")
            and module_protocol not in {"__init__.py", "base.py"}
        ]

    def load(self):
        self.module_content = TemplateLoader(self.module_name, self.module_inputs).load()
        if not self.skip_service_discovery and self.module_name not in self.ignored_core_modules:
            services = {}
            for service in find_events(self.target, "port_scan", self.scan_id):
                service_event = json.loads(service.json_event)
                port = service_event["port"]
                protocols = service_event["response"]["conditions_results"].keys()
                for protocol in protocols:
                    if protocol and protocol in self.libraries:
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
                        step = TemplateLoader.parse(
                            step, {"port": self.discovered_services[payload["library"]]}
                        )
                        self.module_content["payloads"][index_payload]["steps"][index_step] = step
                        index_step += 1
                index_payload += 1

    def generate_loops(self):
        if self.module_inputs["excluded_ports"]:
            excluded_port_set = set(self.module_inputs["excluded_ports"])
            if self.module_content and "ports" in self.module_content["payloads"][0]["steps"][0]:
                all_ports = self.module_content["payloads"][0]["steps"][0]["ports"]
                all_ports[:] = [port for port in all_ports if port not in excluded_port_set]

        self.module_content["payloads"] = expand_module_steps(self.module_content["payloads"])

    def sort_loops(self):
        """
        Sort loops to optimize dependency resolution:
        1. Independent steps first
        2. Steps that generate dependencies (save_to_temp_events_only)
        3. Steps that consume dependencies (dependent_on_temp_event)
        """
        for index in range(len(self.module_content["payloads"])):
            independent_steps = []
            dependency_generators = []
            dependency_consumers = []

            for step in copy.deepcopy(self.module_content["payloads"][index]["steps"]):
                step_response = step[0]["response"] if step and len(step) > 0 else {}

                has_dependency = "dependent_on_temp_event" in step_response
                generates_dependency = "save_to_temp_events_only" in step_response

                if not has_dependency and not generates_dependency:
                    independent_steps.append(step)
                elif generates_dependency and not has_dependency:
                    dependency_generators.append(step)
                elif generates_dependency and has_dependency:
                    dependency_generators.append(step)  # Generator first
                elif has_dependency and not generates_dependency:
                    dependency_consumers.append(step)
                else:
                    independent_steps.append(step)  # Fallback

            # Combine in optimal order
            sorted_steps = independent_steps + dependency_generators + dependency_consumers
            self.module_content["payloads"][index]["steps"] = sorted_steps

            log.verbose_info(
                f"Sorted {len(sorted_steps)} steps: "
                f"{len(independent_steps)} independent, "
                f"{len(dependency_generators)} generators, "
                f"{len(dependency_consumers)} consumers"
            )

    def start(self):
        active_threads = []

        # counting total number of requests
        total_number_of_requests = 0
        for payload in self.module_content["payloads"]:
            if payload["library"] not in self.libraries:
                log.warn(_("library_not_supported").format(payload["library"]))
                return None
            for step in payload["steps"]:
                total_number_of_requests += len(step)

        request_number_counter = 0
        for payload in self.module_content["payloads"]:
            library = payload["library"]
            engine = getattr(
                importlib.import_module(f"nettacker.core.lib.{library.lower()}"),
                f"{library.capitalize()}Engine",
            )()

            for step in payload["steps"]:
                for sub_step in step:
                    # Try to use shared thread pool if available, otherwise use local threads
                    if queue_manager.thread_pool and hasattr(
                        queue_manager.thread_pool, "submit_task"
                    ):
                        # Submit to shared thread pool
                        queue_manager.thread_pool.submit_task(
                            engine.run,
                            sub_step,
                            self.module_name,
                            self.target,
                            self.scan_id,
                            self.module_inputs,
                            self.process_number,
                            self.module_thread_number,
                            self.total_module_thread_number,
                            request_number_counter,
                            total_number_of_requests,
                        )
                    else:
                        # Use local thread (fallback to original behavior)
                        thread = Thread(
                            target=engine.run,
                            args=(
                                sub_step,
                                self.module_name,
                                self.target,
                                self.scan_id,
                                self.module_inputs,
                                self.process_number,
                                self.module_thread_number,
                                self.total_module_thread_number,
                                request_number_counter,
                                total_number_of_requests,
                            ),
                        )
                        thread.name = f"{self.target} -> {self.module_name} -> {sub_step}"
                        thread.start()
                        active_threads.append(thread)

                        # Manage local thread pool size
                        wait_for_threads_to_finish(
                            active_threads,
                            maximum=self.module_inputs["thread_per_host"],
                            terminable=True,
                        )

                    request_number_counter += 1
                    log.verbose_event_info(
                        _("sending_module_request").format(
                            self.process_number,
                            self.module_name,
                            self.target,
                            self.module_thread_number,
                            self.total_module_thread_number,
                            request_number_counter,
                            total_number_of_requests,
                        )
                    )
                    time.sleep(self.module_inputs["time_sleep_between_requests"])

        # Wait for any remaining local threads to finish
        if active_threads:
            wait_for_threads_to_finish(active_threads, maximum=None, terminable=True)
