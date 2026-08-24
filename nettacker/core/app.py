import copy
import json
import os
import shutil
import socket
import sys
from threading import Thread

import multiprocess

from nettacker import logger
from nettacker.config import Config, version_info
from nettacker.core.arg_parser import ArgParser
from nettacker.core.die import die_failure
from nettacker.core.flow import evaluate_depends_on, render_params
from nettacker.core.graph import create_compare_report, create_report
from nettacker.core.ip import (
    generate_ip_range,
    get_ip_range,
    is_ipv4_cidr,
    is_ipv4_range,
    is_ipv6_cidr,
    is_ipv6_range,
    is_single_ipv4,
    is_single_ipv6,
)
from nettacker.core.messages import messages as _
from nettacker.core.module import Module
from nettacker.core.socks_proxy import set_socks_proxy
from nettacker.core.utils import common as common_utils
from nettacker.core.utils.common import wait_for_threads_to_finish
from nettacker.database.db import find_events, remove_old_logs
from nettacker.database.mysql import mysql_create_database, mysql_create_tables
from nettacker.database.postgresql import postgres_create_database
from nettacker.database.sqlite import sqlite_create_tables
from nettacker.logger import TerminalCodes

log = logger.get_logger()


class Nettacker(ArgParser):
    def __init__(self, api_arguments=None):
        if not api_arguments:
            self.print_logo()
        self.check_dependencies()

        log.info(_("scan_started"))
        super().__init__(api_arguments=api_arguments)

    @staticmethod
    def print_logo():
        """
        OWASP Nettacker Logo
        """
        log.write_to_api_console(
            open(Config.path.logo_file)
            .read()
            .format(
                cyan=TerminalCodes.CYAN.value,
                red=TerminalCodes.RED.value,
                rst=TerminalCodes.RESET.value,
                v1=version_info()[0],
                v2=version_info()[1],
                yellow=TerminalCodes.YELLOW.value,
            )
        )
        log.reset_color()

    def check_dependencies(self):
        if sys.platform not in {"darwin", "freebsd13", "freebsd14", "freebsd15", "linux"}:
            die_failure(_("error_platform"))

        try:
            Config.path.tmp_dir.mkdir(exist_ok=True, parents=True)
            Config.path.results_dir.mkdir(exist_ok=True, parents=True)
        except PermissionError:
            die_failure("Cannot access the directory {0}".format(Config.path.tmp_dir))

        if Config.db.engine == "sqlite":
            try:
                if not Config.path.new_database_file.exists():
                    Config.path.new_database_file.parent.mkdir(parents=True, exist_ok=True)
                    if Config.path.old_database_file.exists():
                        shutil.copy(Config.path.old_database_file, Config.path.new_database_file)
                        log.warn("Database files migrated from .data to .nettacker ...")
                    else:
                        sqlite_create_tables()
            except PermissionError:
                die_failure("cannot access the directory {0}".format(Config.path.home_dir))
        elif Config.db.engine == "mysql":
            try:
                mysql_create_database()
                mysql_create_tables()
            except Exception:
                die_failure(_("database_connection_failed"))
        elif Config.db.engine == "postgres":
            try:
                postgres_create_database()
            except Exception:
                die_failure(_("database_connection_failed"))
        else:
            die_failure(_("invalid_database"))

    def expand_targets(self, scan_id):
        """
        determine targets.

        Args:
            options: all options
            scan_id: unique scan identifier

        Returns:
            a generator
        """
        targets = []
        base_path = ""
        for target in self.arguments.targets:
            if "://" in target:
                try:
                    if not target.split("://")[1].split("/")[1]:
                        base_path = ""
                    else:
                        base_path = "/".join(target.split("://")[1].split("/")[1:])
                        if base_path[-1] != "/":
                            base_path += "/"
                except IndexError:
                    base_path = ""
                # remove url proto; uri; port
                target = target.split("://")[1].split("/")[0].split(":")[0]
                targets.append(target)
            # single IPs
            elif is_single_ipv4(target) or is_single_ipv6(target):
                if self.arguments.scan_ip_range:
                    targets += get_ip_range(target)
                else:
                    targets.append(target)
            # IP ranges
            elif (
                is_ipv4_range(target)
                or is_ipv6_range(target)
                or is_ipv4_cidr(target)
                or is_ipv6_cidr(target)
            ):
                targets += generate_ip_range(target)
            # domains probably
            else:
                targets.append(target)
        self.arguments.targets = targets
        self.arguments.url_base_path = base_path

        # subdomain_scan
        if self.arguments.scan_subdomains:
            selected_modules = self.arguments.selected_modules
            flow = self.arguments.flow
            self.arguments.selected_modules = ["subdomain_scan"]
            self.arguments.flow = None
            self.start_scan(scan_id)
            self.arguments.selected_modules = selected_modules
            self.arguments.flow = flow
            if "subdomain_scan" in self.arguments.selected_modules:
                self.arguments.selected_modules.remove("subdomain_scan")

            for target in copy.deepcopy(self.arguments.targets):
                for row in find_events(target, "subdomain_scan", scan_id):
                    for sub_domain in json.loads(row)["response"]["conditions_results"]["content"]:
                        if sub_domain not in self.arguments.targets:
                            self.arguments.targets.append(sub_domain)
        # icmp_scan
        if self.arguments.ping_before_scan:
            if os.geteuid() == 0:
                selected_modules = self.arguments.selected_modules
                flow = self.arguments.flow
                self.arguments.selected_modules = ["icmp_scan"]
                self.arguments.flow = None
                self.start_scan(scan_id)
                self.arguments.selected_modules = selected_modules
                self.arguments.flow = flow
                if "icmp_scan" in self.arguments.selected_modules:
                    self.arguments.selected_modules.remove("icmp_scan")
                self.arguments.targets = self.filter_target_by_event(targets, scan_id, "icmp_scan")
            else:
                log.warn(_("icmp_need_root_access"))
                if "icmp_scan" in self.arguments.selected_modules:
                    self.arguments.selected_modules.remove("icmp_scan")
        # port_scan
        if not self.arguments.skip_service_discovery:
            self.arguments.skip_service_discovery = True
            selected_modules = self.arguments.selected_modules
            flow = self.arguments.flow
            self.arguments.selected_modules = ["port_scan"]
            self.arguments.flow = None
            self.start_scan(scan_id)
            self.arguments.selected_modules = selected_modules
            self.arguments.flow = flow
            if "port_scan" in self.arguments.selected_modules:
                self.arguments.selected_modules.remove("port_scan")
            self.arguments.targets = self.filter_target_by_event(targets, scan_id, "port_scan")
            self.arguments.skip_service_discovery = False
        return list(set(self.arguments.targets))

    def filter_target_by_event(self, targets, scan_id, module_name):
        for target in copy.deepcopy(targets):
            if not find_events(target, module_name, scan_id):
                targets.remove(target)
        return targets

    def run(self):
        """
        preparing for attacks and managing multi-processing for host

        Args:
            options: all options

        Returns:
            True when it ends
        """
        scan_id = common_utils.generate_random_token(32)
        log.info("ScanID: {0}".format(scan_id))
        log.info(_("regrouping_targets"))
        # find total number of targets + types + expand (subdomain, IPRanges, etc)
        # optimize CPU usage
        self.arguments.targets = self.expand_targets(scan_id)
        if not self.arguments.targets:
            log.info(_("no_live_service_found"))
            return True
        exit_code = self.start_scan(scan_id)
        create_report(self.arguments, scan_id)
        if self.arguments.scan_compare_id is not None:
            create_compare_report(self.arguments, scan_id)
        log.info("ScanID: {0} ".format(scan_id) + _("done"))

        return exit_code

    def start_scan(self, scan_id):
        target_groups = common_utils.generate_target_groups(
            self.arguments.targets, self.arguments.set_hardware_usage
        )
        log.info(_("removing_old_db_records"))

        for target_group in target_groups:
            for target in target_group:
                for module_name in self.arguments.selected_modules:
                    remove_old_logs(
                        {
                            "target": target,
                            "module_name": module_name,
                            "scan_id": scan_id,
                            "scan_compare_id": self.arguments.scan_compare_id,
                        }
                    )

        for _i in range(target_groups.count([])):
            target_groups.remove([])

        log.info(_("start_multi_process").format(len(self.arguments.targets), len(target_groups)))
        active_processes = []
        for t_id, target_groups in enumerate(target_groups):
            process = multiprocess.Process(
                target=self.scan_target_group, args=(target_groups, scan_id, t_id)
            )
            process.start()
            active_processes.append(process)

        return wait_for_threads_to_finish(active_processes, sub_process=True)

    def scan_target(
        self,
        target,
        module_name,
        scan_id,
        process_number,
        thread_number,
        total_number_threads,
        extra_options=None,
    ):
        options = copy.deepcopy(self.arguments)
        if extra_options:
            for key, value in extra_options.items():
                if value is not None:
                    setattr(options, key, value)

        socket.socket, socket.getaddrinfo = set_socks_proxy(options.socks_proxy)
        module = Module(
            module_name,
            options,
            target,
            scan_id,
            process_number,
            thread_number,
            total_number_threads,
        )
        module.load()
        module.generate_loops()
        module.sort_loops()
        module.start()

        log.verbose_event_info(
            _("finished_parallel_module_scan").format(
                process_number, module_name, target, thread_number, total_number_threads
            )
        )

        return os.EX_OK

    def scan_target_group(self, targets, scan_id, process_number):
        active_threads = []
        log.verbose_event_info(_("single_process_started").format(process_number))
        flow = getattr(self.arguments, "flow", None)
        if not flow:
            total_number_of_modules = len(targets) * len(self.arguments.selected_modules)
            total_number_of_modules_counter = 1
            for target in targets:
                for module_name in self.arguments.selected_modules:
                    thread = Thread(
                        target=self.scan_target,
                        args=(
                            target,
                            module_name,
                            scan_id,
                            process_number,
                            total_number_of_modules_counter,
                            total_number_of_modules,
                        ),
                    )
                    thread.name = f"{target} -> {module_name}"
                    thread.start()
                    log.verbose_event_info(
                        _("start_parallel_module_scan").format(
                            process_number,
                            module_name,
                            target,
                            total_number_of_modules_counter,
                            total_number_of_modules,
                        )
                    )
                    total_number_of_modules_counter += 1
                    active_threads.append(thread)
                    if not wait_for_threads_to_finish(
                        active_threads, self.arguments.parallel_module_scan, True
                    ):
                        return False
            wait_for_threads_to_finish(active_threads, maximum=None, terminable=True)
            return True

        return self.scan_flow_group(flow, targets, scan_id, process_number, active_threads)

    def scan_flow_group(self, flow, targets, scan_id, process_number, active_threads):
        """
        Run a YAML-defined module flow against a group of targets: steps are scheduled
        as soon as their `depends_on` expression is satisfied (dependencies may be a
        plain list, or nested any/all trees), independently per target.
        """
        steps_by_id = {step.id: step for step in flow.steps}
        max_parallel = min(self.arguments.parallel_module_scan, flow.max_parallel)
        flow_inputs = self.arguments.flow_inputs or {}

        total_number_of_modules = len(targets) * len(steps_by_id)
        total_number_of_modules_counter = 1

        target_state = {
            target: {"completed": set(), "blocked": set(), "running": set(), "aborted": False}
            for target in targets
        }

        step_threads = {}

        while True:
            work_remaining = False
            for target in targets:
                state = target_state[target]
                if state["aborted"] or len(state["completed"]) + len(state["blocked"]) == len(
                    steps_by_id
                ):
                    continue
                work_remaining = True

                for step_id, step in steps_by_id.items():
                    if (
                        step_id in state["completed"]
                        or step_id in state["blocked"]
                        or step_id in state["running"]
                    ):
                        continue

                    status = evaluate_depends_on(
                        step.depends_on, state["completed"], state["blocked"]
                    )
                    if status == "blocked":
                        state["blocked"].add(step_id)
                        continue
                    if status == "pending":
                        continue

                    # launch step
                    context = {**flow_inputs, "target": target}
                    extra_options = render_params(step.params, context)
                    effective_timeout = step.timeout if step.timeout is not None else flow.timeout
                    effective_retries = step.retries if step.retries is not None else flow.retries
                    if effective_timeout is not None:
                        extra_options["timeout"] = effective_timeout
                    if effective_retries is not None:
                        extra_options["retries"] = effective_retries

                    thread = Thread(
                        target=self.scan_target,
                        args=(
                            target,
                            step.module,
                            scan_id,
                            process_number,
                            total_number_of_modules_counter,
                            total_number_of_modules,
                            extra_options,
                        ),
                    )
                    thread.name = f"{target} -> {step_id} ({step.module})"
                    thread.start()

                    log.verbose_event_info(
                        _("start_parallel_module_scan").format(
                            process_number,
                            step.module,
                            target,
                            total_number_of_modules_counter,
                            total_number_of_modules,
                        )
                    )

                    total_number_of_modules_counter += 1

                    active_threads.append(thread)
                    state["running"].add(step_id)
                    step_threads[(target, step_id)] = thread

                    if not wait_for_threads_to_finish(active_threads, max_parallel, True):
                        return False

            # detect finished threads
            for (target, step_id), thread in list(step_threads.items()):
                if not thread.is_alive():
                    step = steps_by_id[step_id]
                    state = target_state[target]
                    state["running"].remove(step_id)

                    # success is tracked per (target, module_name, scan_id) in the database,
                    # so two steps invoking the same module share this success signal
                    if find_events(target, step.module, scan_id):
                        state["completed"].add(step_id)
                    else:
                        state["blocked"].add(step_id)
                        if (step.on_failure or flow.on_failure) == "abort":
                            state["aborted"] = True

                    del step_threads[(target, step_id)]

            if not work_remaining and not step_threads:
                break

            if not wait_for_threads_to_finish(active_threads, max_parallel, True):
                return False

        wait_for_threads_to_finish(active_threads, maximum=None, terminable=True)
        return True
