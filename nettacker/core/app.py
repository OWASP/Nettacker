import copy
import json
import os
import socket
import sys
from threading import Thread

import multiprocess

from nettacker import logger
from nettacker.config import Config, version_info
from nettacker.core.arg_parser import ArgParser
from nettacker.core.die import die_failure
from nettacker.core.graph import create_report, create_compare_report
from nettacker.core.ip import (
    get_ip_range,
    generate_ip_range,
    is_single_ipv4,
    is_ipv4_range,
    is_ipv4_cidr,
    is_single_ipv6,
    is_ipv6_range,
    is_ipv6_cidr,
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
        if sys.platform not in {"darwin", "linux"}:
            die_failure(_("error_platform"))

        try:
            Config.path.tmp_dir.mkdir(exist_ok=True, parents=True)
            Config.path.results_dir.mkdir(exist_ok=True, parents=True)
        except PermissionError:
            die_failure("Cannot access the directory {0}".format(Config.path.tmp_dir))

        if Config.db.engine == "sqlite":
            try:
                if not Config.path.database_file.exists():
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
        for target in self.arguments.targets:
            if "://" in target:
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

        # subdomain_scan
        if self.arguments.scan_subdomains:
            selected_modules = self.arguments.selected_modules
            self.arguments.selected_modules = ["subdomain_scan"]
            self.start_scan(scan_id)
            self.arguments.selected_modules = selected_modules
            if "subdomain_scan" in self.arguments.selected_modules:
                self.arguments.selected_modules.remove("subdomain_scan")

            for target in copy.deepcopy(self.arguments.targets):
                for row in find_events(target, "subdomain_scan", scan_id):
                    for sub_domain in json.loads(row.json_event)["response"]["conditions_results"][
                        "content"
                    ]:
                        if sub_domain not in self.arguments.targets:
                            self.arguments.targets.append(sub_domain)
        # icmp_scan
        if self.arguments.ping_before_scan:
            if os.geteuid() == 0:
                selected_modules = self.arguments.selected_modules
                self.arguments.selected_modules = ["icmp_scan"]
                self.start_scan(scan_id)
                self.arguments.selected_modules = selected_modules
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
            self.arguments.selected_modules = ["port_scan"]
            self.start_scan(scan_id)
            self.arguments.selected_modules = selected_modules
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
    ):
        options = copy.deepcopy(self.arguments)

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
