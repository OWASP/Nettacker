import copy
import json
import re
import time
from abc import ABC
from datetime import datetime

import yaml

from nettacker.config import Config
from nettacker.core.messages import messages as _
from nettacker.core.utils.common import merge_logs_to_list
from nettacker.database.db import find_temp_events, submit_temp_logs_to_db, submit_logs_to_db
from nettacker.logger import get_logger, TerminalCodes

log = get_logger()


class BaseLibrary(ABC):
    """Nettacker library base class."""

    client = None

    def brute_force(self):
        """Brute force method."""


class BaseEngine(ABC):
    """Nettacker engine base class."""

    library = None

    def apply_extra_data(self, *args, **kwargs):
        """Add extra data into step context."""

    def filter_large_content(self, content, filter_rate=150):
        if len(content) <= filter_rate:
            return content
        else:
            filter_rate -= 1
            filter_index = filter_rate
            for char in content[filter_rate:]:
                if char == " ":
                    return content[0:filter_index] + _("filtered_content")
                else:
                    filter_index += 1
            return content

    def get_dependent_results_from_database(self, target, module_name, scan_id, event_names):
        events = []
        for event_name in event_names.split(","):
            while True:
                event = find_temp_events(target, module_name, scan_id, event_name)
                if event:
                    events.append(json.loads(event.event)["response"]["conditions_results"])
                    break
                time.sleep(0.1)
        return events

    def find_and_replace_dependent_values(self, sub_step, dependent_on_temp_event):
        if isinstance(sub_step, dict):
            for key in copy.deepcopy(sub_step):
                if not isinstance(sub_step[key], (str, float, int, bytes)):
                    sub_step[key] = self.find_and_replace_dependent_values(
                        copy.deepcopy(sub_step[key]), dependent_on_temp_event
                    )
                else:
                    if isinstance(sub_step[key], str):
                        if "dependent_on_temp_event" in sub_step[key]:
                            globals().update(locals())
                            generate_new_step = copy.deepcopy(sub_step[key])
                            key_name = re.findall(
                                re.compile(
                                    "dependent_on_temp_event\\[\\S+\\]\\['\\S+\\]\\[\\S+\\]"
                                ),
                                generate_new_step,
                            )[0]
                            try:
                                key_value = eval(key_name)
                            except Exception:
                                key_value = "error"
                            sub_step[key] = sub_step[key].replace(key_name, key_value)
        if isinstance(sub_step, list):
            value_index = 0
            for key in copy.deepcopy(sub_step):
                if type(sub_step[value_index]) not in [str, float, int, bytes]:
                    sub_step[key] = self.find_and_replace_dependent_values(
                        copy.deepcopy(sub_step[value_index]), dependent_on_temp_event
                    )
                else:
                    if isinstance(sub_step[value_index], str):
                        if "dependent_on_temp_event" in sub_step[value_index]:
                            globals().update(locals())
                            generate_new_step = copy.deepcopy(sub_step[key])
                            key_name = re.findall(
                                re.compile("dependent_on_temp_event\\['\\S+\\]\\[\\S+\\]"),
                                generate_new_step,
                            )[0]
                            try:
                                key_value = eval(key_name)
                            except Exception:
                                key_value = "error"
                            sub_step[value_index] = sub_step[value_index].replace(
                                key_name, key_value
                            )
                value_index += 1
        return sub_step

    def process_conditions(
        self,
        event,
        module_name,
        target,
        scan_id,
        options,
        response,
        process_number,
        module_thread_number,
        total_module_thread_number,
        request_number_counter,
        total_number_of_requests,
    ):
        if "save_to_temp_events_only" in event.get("response", ""):
            submit_temp_logs_to_db(
                {
                    "date": datetime.now(),
                    "target": target,
                    "module_name": module_name,
                    "scan_id": scan_id,
                    "event_name": event["response"]["save_to_temp_events_only"],
                    "port": event.get("ports", ""),
                    "event": event,
                    "data": response,
                }
            )
        if event["response"]["conditions_results"] and "save_to_temp_events_only" not in event.get(
            "response", ""
        ):
            # remove sensitive information before submitting to db

            options = copy.deepcopy(options)
            for key in Config.api:
                try:
                    del options[key]
                except KeyError:
                    continue

            del event["response"]["conditions"]
            del event["response"]["condition_type"]
            if "log" in event["response"]:
                del event["response"]["log"]
            event_request_keys = copy.deepcopy(event)
            del event_request_keys["response"]
            submit_logs_to_db(
                {
                    "date": datetime.now(),
                    "target": target,
                    "module_name": module_name,
                    "scan_id": scan_id,
                    "port": event.get("ports")
                    or event.get("port")
                    or (
                        event.get("url").split(":")[2].split("/")[0]
                        if isinstance(event.get("url"), str)
                        and len(event.get("url").split(":")) >= 3
                        and event.get("url").split(":")[2].split("/")[0].isdigit()
                        else ""
                    ),
                    "event": " ".join(yaml.dump(event_request_keys).split())
                    + " conditions: "
                    + " ".join(yaml.dump(event["response"]["conditions_results"]).split()),
                    "json_event": event,
                }
            )
            log_list = merge_logs_to_list(event["response"]["conditions_results"])
            if log_list:
                log.success_event_info(
                    _("send_success_event_from_module").format(
                        process_number,
                        module_name,
                        target,
                        module_thread_number,
                        total_module_thread_number,
                        request_number_counter,
                        total_number_of_requests,
                        " ",
                        self.filter_large_content(
                            "\n".join(
                                [
                                    TerminalCodes.PURPLE.value + key + TerminalCodes.RESET.value
                                    for key in log_list
                                ]
                            ),
                            filter_rate=100000,
                        ),
                    )
                )
            else:
                log.success_event_info(
                    _("send_success_event_from_module").format(
                        process_number,
                        module_name,
                        target,
                        module_thread_number,
                        total_module_thread_number,
                        request_number_counter,
                        total_number_of_requests,
                        " ".join(
                            [
                                TerminalCodes.YELLOW.value + key + TerminalCodes.RESET.value
                                if ":" in key
                                else TerminalCodes.GREEN.value + key + TerminalCodes.RESET.value
                                for key in yaml.dump(event_request_keys).split()
                            ]
                        ),
                        self.filter_large_content(
                            "conditions: "
                            + " ".join(
                                [
                                    TerminalCodes.PURPLE.value + key + TerminalCodes.RESET.value
                                    if ":" in key
                                    else TerminalCodes.GREEN.value
                                    + key
                                    + TerminalCodes.RESET.value
                                    for key in yaml.dump(
                                        event["response"]["conditions_results"]
                                    ).split()
                                ]
                            ),
                            filter_rate=150,
                        ),
                    )
                )
            log.verbose_info(json.dumps(event))
            return True
        else:
            del event["response"]["conditions"]
            log.verbose_info(
                _("send_unsuccess_event_from_module").format(
                    process_number,
                    module_name,
                    target,
                    module_thread_number,
                    total_module_thread_number,
                    request_number_counter,
                    total_number_of_requests,
                )
            )
            log.verbose_info(json.dumps(event))
            return "save_to_temp_events_only" in event["response"]

    def replace_dependent_values(self, sub_step, dependent_on_temp_event):
        return self.find_and_replace_dependent_values(sub_step, dependent_on_temp_event)

    def run(
        self,
        sub_step,
        module_name,
        target,
        scan_id,
        options,
        process_number,
        module_thread_number,
        total_module_thread_number,
        request_number_counter,
        total_number_of_requests,
    ):
        """Engine entry point."""
        backup_method = copy.deepcopy(sub_step["method"])
        backup_response = copy.deepcopy(sub_step["response"])
        del sub_step["method"]
        del sub_step["response"]

        for attr_name in ("ports", "usernames", "passwords"):
            if attr_name in sub_step:
                value = sub_step.pop(attr_name)
                sub_step[attr_name.rstrip("s")] = int(value) if attr_name == "ports" else value

        if "dependent_on_temp_event" in backup_response:
            temp_event = self.get_dependent_results_from_database(
                target, module_name, scan_id, backup_response["dependent_on_temp_event"]
            )
            sub_step = self.replace_dependent_values(sub_step, temp_event)

        action = getattr(self.library(), backup_method)
        for _i in range(options["retries"]):
            try:
                response = action(**sub_step)
                break
            except Exception:
                response = []

        sub_step["method"] = backup_method
        sub_step["response"] = backup_response
        sub_step["response"]["conditions_results"] = response

        self.apply_extra_data(sub_step, response)

        return self.process_conditions(
            sub_step,
            module_name,
            target,
            scan_id,
            options,
            response,
            process_number,
            module_thread_number,
            total_module_thread_number,
            request_number_counter,
            total_number_of_requests,
        )
