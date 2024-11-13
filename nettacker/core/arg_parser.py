import json
import sys
from argparse import ArgumentParser

import yaml

from nettacker.config import version_info, Config
from nettacker.core.die import die_failure, die_success
from nettacker.core.ip import (
    is_single_ipv4,
    is_single_ipv6,
    is_ipv4_cidr,
    is_ipv6_range,
    is_ipv6_cidr,
    is_ipv4_range,
    generate_ip_range,
)
from nettacker.core.messages import messages as _
from nettacker.core.template import TemplateLoader
from nettacker.core.utils import common as common_utils
from nettacker.logger import TerminalCodes, get_logger

log = get_logger()


class ArgParser(ArgumentParser):
    def __init__(self, api_arguments=None) -> None:
        super().__init__(prog="Nettacker", add_help=False)

        self.api_arguments = api_arguments
        self.graphs = self.load_graphs()
        self.languages = self.load_languages()

        self.modules = self.load_modules(full_details=True)
        log.info(_("loaded_modules").format(len(self.modules)))

        self.profiles = self.load_profiles()

        self.add_arguments()
        self.parse_arguments()

    @staticmethod
    def load_graphs():
        """
        load all available graphs

        Returns:
            an array of graph names
        """

        graph_names = []
        for graph_library in Config.path.graph_dir.glob("*/engine.py"):
            graph_names.append(str(graph_library).split("/")[-2] + "_graph")
        return list(set(graph_names))

    @staticmethod
    def load_languages():
        """
        Get available languages

        Returns:
            an array of languages
        """
        languages_list = []

        for language in Config.path.locale_dir.glob("*.yaml"):
            languages_list.append(str(language).split("/")[-1].split(".")[0])

        return list(set(languages_list))

    @staticmethod
    def load_modules(limit=-1, full_details=False):
        """
        load all available modules

        limit: return limited number of modules
        full: with full details

        Returns:
            an array of all module names
        """
        # Search for Modules

        module_names = {}
        for module_name in sorted(Config.path.modules_dir.glob("**/*.yaml")):
            library = str(module_name).split("/")[-1].split(".")[0]
            category = str(module_name).split("/")[-2]
            module = f"{library}_{category}"
            contents = yaml.safe_load(TemplateLoader(module).open().split("payload:")[0])
            module_names[module] = contents["info"] if full_details else None

            if len(module_names) == limit:
                module_names["..."] = {}
                break
        module_names = common_utils.sort_dictionary(module_names)
        module_names["all"] = {}

        return module_names

    @staticmethod
    def load_profiles(limit=-1):
        """
        load all available profiles

        Returns:
            an array of all profile names
        """
        all_modules_with_details = ArgParser.load_modules(full_details=True).copy()
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
                    profiles = common_utils.sort_dictionary(profiles)
                    profiles["..."] = []
                    profiles["all"] = []
                    return profiles
        profiles = common_utils.sort_dictionary(profiles)
        profiles["all"] = []

        return profiles

    def add_arguments(self):
        # Engine Options
        engine_options = self.add_argument_group(_("engine"), _("engine_input"))
        engine_options.add_argument(
            "-L",
            "--language",
            action="store",
            dest="language",
            default=Config.settings.language,
            help=_("select_language").format(self.languages),
        )
        engine_options.add_argument(
            "-v",
            "--verbose",
            action="store_true",
            dest="verbose_mode",
            default=Config.settings.verbose_mode,
            help=_("verbose_mode"),
        )
        engine_options.add_argument(
            "--verbose-event",
            action="store_true",
            dest="verbose_event",
            default=Config.settings.verbose_event,
            help=_("verbose_event"),
        )
        engine_options.add_argument(
            "-V",
            "--version",
            action="store_true",
            default=Config.settings.show_version,
            dest="show_version",
            help=_("software_version"),
        )
        engine_options.add_argument(
            "-o",
            "--output",
            action="store",
            default=Config.settings.report_path_filename,
            dest="report_path_filename",
            help=_("save_logs"),
        )
        engine_options.add_argument(
            "--graph",
            action="store",
            default=Config.settings.graph_name,
            dest="graph_name",
            help=_("available_graph").format(self.graphs),
        )
        engine_options.add_argument(
            "-h",
            "--help",
            action="store_true",
            default=Config.settings.show_help_menu,
            dest="show_help_menu",
            help=_("help_menu"),
        )

        # Target Options
        target_options = self.add_argument_group(_("target"), _("target_input"))
        target_options.add_argument(
            "-i",
            "--targets",
            action="store",
            dest="targets",
            default=Config.settings.targets,
            help=_("target_list"),
        )
        target_options.add_argument(
            "-l",
            "--targets-list",
            action="store",
            dest="targets_list",
            default=Config.settings.targets_list,
            help=_("read_target"),
        )

        # Exclude Module Name
        exclude_modules = sorted(self.modules.keys())[:10]
        exclude_modules.remove("all")

        # Method Options
        method_options = self.add_argument_group(_("Method"), _("scan_method_options"))
        method_options.add_argument(
            "-m",
            "--modules",
            action="store",
            dest="selected_modules",
            default=Config.settings.selected_modules,
            help=_("choose_scan_method").format(list(self.modules.keys())[:10]),
        )
        method_options.add_argument(
            "--modules-extra-args",
            action="store",
            dest="modules_extra_args",
            default=Config.settings.modules_extra_args,
            help=_("modules_extra_args_help"),
        )
        method_options.add_argument(
            "--show-all-modules",
            action="store_true",
            dest="show_all_modules",
            default=Config.settings.show_all_modules,
            help=_("show_all_modules"),
        )
        method_options.add_argument(
            "--profile",
            action="store",
            default=Config.settings.profiles,
            dest="profiles",
            help=_("select_profile").format(list(self.profiles.keys())[:10]),
        )
        method_options.add_argument(
            "--show-all-profiles",
            action="store_true",
            dest="show_all_profiles",
            default=Config.settings.show_all_profiles,
            help=_("show_all_profiles"),
        )
        method_options.add_argument(
            "-x",
            "--exclude-modules",
            action="store",
            dest="excluded_modules",
            default=Config.settings.excluded_modules,
            help=_("exclude_scan_method").format(exclude_modules),
        )
        method_options.add_argument(
            "-u",
            "--usernames",
            action="store",
            dest="usernames",
            default=Config.settings.usernames,
            help=_("username_list"),
        )
        method_options.add_argument(
            "-U",
            "--users-list",
            action="store",
            dest="usernames_list",
            default=Config.settings.usernames_list,
            help=_("username_from_file"),
        )
        method_options.add_argument(
            "-p",
            "--passwords",
            action="store",
            dest="passwords",
            default=Config.settings.passwords,
            help=_("password_separator"),
        )
        method_options.add_argument(
            "-P",
            "--passwords-list",
            action="store",
            dest="passwords_list",
            default=Config.settings.passwords_list,
            help=_("read_passwords"),
        )
        method_options.add_argument(
            "-g",
            "--ports",
            action="store",
            dest="ports",
            default=Config.settings.ports,
            help=_("port_separator"),
        )
        method_options.add_argument(
            "--user-agent",
            action="store",
            dest="user_agent",
            default=Config.settings.user_agent,
            help=_("select_user_agent"),
        )
        method_options.add_argument(
            "-T",
            "--timeout",
            action="store",
            dest="timeout",
            default=Config.settings.timeout,
            type=float,
            help=_("read_passwords"),
        )
        method_options.add_argument(
            "-w",
            "--time-sleep-between-requests",
            action="store",
            dest="time_sleep_between_requests",
            default=Config.settings.time_sleep_between_requests,
            type=float,
            help=_("time_to_sleep"),
        )
        method_options.add_argument(
            "-r",
            "--range",
            action="store_true",
            default=Config.settings.scan_ip_range,
            dest="scan_ip_range",
            help=_("range"),
        )
        method_options.add_argument(
            "-s",
            "--sub-domains",
            action="store_true",
            default=Config.settings.scan_subdomains,
            dest="scan_subdomains",
            help=_("subdomains"),
        )
        method_options.add_argument(
            "-d",
            "--skip-service-discovery",
            action="store_true",
            default=Config.settings.skip_service_discovery,
            dest="skip_service_discovery",
            help=_("skip_service_discovery"),
        )
        method_options.add_argument(
            "-t",
            "--thread-per-host",
            action="store",
            default=Config.settings.thread_per_host,
            type=int,
            dest="thread_per_host",
            help=_("thread_number_connections"),
        )
        method_options.add_argument(
            "-M",
            "--parallel-module-scan",
            action="store",
            default=Config.settings.parallel_module_scan,
            type=int,
            dest="parallel_module_scan",
            help=_("thread_number_modules"),
        )
        method_options.add_argument(
            "--set-hardware-usage",
            action="store",
            dest="set_hardware_usage",
            default=Config.settings.set_hardware_usage,
            help=_("set_hardware_usage"),
        )
        method_options.add_argument(
            "-R",
            "--socks-proxy",
            action="store",
            dest="socks_proxy",
            default=Config.settings.socks_proxy,
            help=_("outgoing_proxy"),
        )
        method_options.add_argument(
            "--retries",
            action="store",
            dest="retries",
            type=int,
            default=Config.settings.retries,
            help=_("connection_retries"),
        )
        method_options.add_argument(
            "--ping-before-scan",
            action="store_true",
            dest="ping_before_scan",
            default=Config.settings.ping_before_scan,
            help=_("ping_before_scan"),
        )
        method_options.add_argument(
            "-K",
            "--scan-compare",
            action="store",
            dest="scan_compare_id",
            default=Config.settings.scan_compare_id,
            help=_("compare_scans"),
        )
        method_options.add_argument(
            "-J",
            "--compare-report-path",
            action="store",
            dest="compare_report_path_filename",
            default=Config.settings.compare_report_path_filename,
            help=_("compare_report_path_filename"),
        )

        # API Options
        api_options = self.add_argument_group(_("API"), _("API_options"))
        api_options.add_argument(
            "--start-api",
            action="store_true",
            dest="start_api_server",
            default=Config.api.start_api_server,
            help=_("start_api_server"),
        )
        api_options.add_argument(
            "--api-host",
            action="store",
            dest="api_hostname",
            default=Config.api.api_hostname,
            help=_("API_host"),
        )
        api_options.add_argument(
            "--api-port",
            action="store",
            dest="api_port",
            default=Config.api.api_port,
            help=_("API_port"),
        )
        api_options.add_argument(
            "--api-debug-mode",
            action="store_true",
            dest="api_debug_mode",
            default=Config.api.api_debug_mode,
            help=_("API_debug"),
        )
        api_options.add_argument(
            "--api-access-key",
            action="store",
            dest="api_access_key",
            default=Config.api.api_access_key,
            help=_("API_access_key"),
        )
        api_options.add_argument(
            "--api-client-whitelisted-ips",
            action="store",
            dest="api_client_whitelisted_ips",
            default=Config.api.api_client_whitelisted_ips,
            help=_("define_white_list"),
        )
        api_options.add_argument(
            "--api-access-log",
            action="store",
            dest="api_access_log",
            default=Config.api.api_access_log,
            help=_("API_access_log_file"),
        )
        api_options.add_argument(
            "--api-cert",
            action="store",
            dest="api_cert",
            help=_("API_cert"),
        )
        api_options.add_argument(
            "--api-cert-key",
            action="store",
            dest="api_cert_key",
            help=_("API_cert_key"),
        )

    def parse_arguments(self):
        """
        check all rules and requirements for ARGS

        Args:
            api_forms: values from nettacker.api

        Returns:
            all ARGS with applied rules
        """
        # Checking Requirements
        options = self.api_arguments or self.parse_args()

        if options.language not in self.languages:
            die_failure("Please select one of these languages {0}".format(self.languages))

        # Check Help Menu
        if options.show_help_menu:
            self.print_help()
            log.write("\n\n")
            log.write(_("license"))
            die_success()

        # Check version
        if options.show_version:
            log.info(
                _("current_version").format(
                    TerminalCodes.YELLOW.value,
                    version_info()[0],
                    TerminalCodes.RESET.value,
                    TerminalCodes.CYAN.value,
                    version_info()[1],
                    TerminalCodes.RESET.value,
                    TerminalCodes.GREEN.value,
                )
            )
            die_success()

        if options.show_all_modules:
            log.info(_("loading_modules"))
            for module in self.modules:
                log.info(
                    _("module_profile_full_information").format(
                        TerminalCodes.CYAN.value,
                        module,
                        TerminalCodes.GREEN.value,
                        ", ".join(
                            [
                                "{key}: {value}".format(key=key, value=self.modules[module][key])
                                for key in self.modules[module]
                            ]
                        ),
                    )
                )
            die_success()

        if options.show_all_profiles:
            log.info(_("loading_profiles"))
            for profile in self.profiles:
                log.info(
                    _("module_profile_full_information").format(
                        TerminalCodes.CYAN.value,
                        profile,
                        TerminalCodes.GREEN.value,
                        ", ".join(self.profiles[profile]),
                    )
                )
            die_success()

        # API mode
        if options.start_api_server:
            if "--start-api" in sys.argv and self.api_arguments:
                die_failure(_("cannot_run_api_server"))
            from nettacker.api.engine import start_api_server

            if options.api_client_whitelisted_ips:
                if isinstance(options.api_client_whitelisted_ips, str):
                    options.api_client_whitelisted_ips = options.api_client_whitelisted_ips.split(
                        ","
                    )
                    whitelisted_ips = []
                    for ip in options.api_client_whitelisted_ips:
                        if is_single_ipv4(ip) or is_single_ipv6(ip):
                            whitelisted_ips.append(ip)
                        elif (
                            is_ipv4_range(ip)
                            or is_ipv6_range(ip)
                            or is_ipv4_cidr(ip)
                            or is_ipv6_cidr(ip)
                        ):
                            whitelisted_ips += generate_ip_range(ip)
                    options.api_client_whitelisted_ips = whitelisted_ips
            start_api_server(options)

        # Check the target(s)
        if not (options.targets or options.targets_list) or (
            options.targets and options.targets_list
        ):
            # self.print_help()
            # write("\n")
            die_failure(_("error_target"))
        if options.targets:
            options.targets = list(set(options.targets.split(",")))
        if options.targets_list:
            try:
                options.targets = list(
                    set(open(options.targets_list, "rb").read().decode().split())
                )
            except Exception:
                die_failure(_("error_target_file").format(options.targets_list))

        # check for modules
        if not (options.selected_modules or options.profiles):
            die_failure(_("scan_method_select"))
        if options.selected_modules:
            if options.selected_modules == "all":
                options.selected_modules = list(set(self.modules.keys()))
                options.selected_modules.remove("all")
            else:
                options.selected_modules = list(set(options.selected_modules.split(",")))
            for module_name in options.selected_modules:
                if module_name not in self.modules:
                    die_failure(_("scan_module_not_found").format(module_name))
        if options.profiles:
            if not options.selected_modules:
                options.selected_modules = []
            if options.profiles == "all":
                options.selected_modules = list(set(self.modules.keys()))
                options.selected_modules.remove("all")
            else:
                options.profiles = list(set(options.profiles.split(",")))
                for profile in options.profiles:
                    if profile not in self.profiles:
                        die_failure(_("profile_404").format(profile))
                    for module_name in self.profiles[profile]:
                        if module_name not in options.selected_modules:
                            options.selected_modules.append(module_name)
        # threading & processing
        if options.set_hardware_usage not in {"low", "normal", "high", "maximum"}:
            die_failure(_("wrong_hardware_usage"))
        options.set_hardware_usage = common_utils.select_maximum_cpu_core(
            options.set_hardware_usage
        )

        options.thread_per_host = int(options.thread_per_host)
        if options.thread_per_host < 1:
            options.thread_per_host = 1
        options.parallel_module_scan = int(options.parallel_module_scan)
        if options.parallel_module_scan < 1:
            options.parallel_module_scan = 1

        # Check for excluding modules
        if options.excluded_modules:
            options.excluded_modules = options.excluded_modules.split(",")
            if "all" in options.excluded_modules:
                die_failure(_("error_exclude_all"))
            for excluded_module in options.excluded_modules:
                if excluded_module in options.selected_modules:
                    options.selected_modules.remove(excluded_module)
        # Check port(s)
        if options.ports:
            tmp_ports = []
            for port in options.ports.split(","):
                try:
                    if "-" in port:
                        for port_number in range(
                            int(port.split("-")[0]), int(port.split("-")[1]) + 1
                        ):
                            if port_number not in tmp_ports:
                                tmp_ports.append(port_number)
                    else:
                        if int(port) not in tmp_ports:
                            tmp_ports.append(int(port))
                except Exception:
                    die_failure(_("ports_int"))
            options.ports = tmp_ports

        if options.user_agent == "random_user_agent":
            options.user_agents = open(Config.path.user_agents_file).read().split("\n")

        # Check user list
        if options.usernames:
            options.usernames = list(set(options.usernames.split(",")))
        elif options.usernames_list:
            try:
                options.usernames = list(set(open(options.usernames_list).read().split("\n")))
            except Exception:
                die_failure(_("error_username").format(options.usernames_list))
        # Check password list
        if options.passwords:
            options.passwords = list(set(options.passwords.split(",")))
        elif options.passwords_list:
            try:
                options.passwords = list(set(open(options.passwords_list).read().split("\n")))
            except Exception:
                die_failure(_("error_passwords").format(options.passwords_list))
        # Check output file
        try:
            temp_file = open(options.report_path_filename, "w")
            temp_file.close()
        except Exception:
            die_failure(_("file_write_error").format(options.report_path_filename))
        # Check Graph
        if options.graph_name:
            if options.graph_name not in self.graphs:
                die_failure(_("graph_module_404").format(options.graph_name))
            if not (
                options.report_path_filename.endswith(".html")
                or options.report_path_filename.endswith(".htm")
            ):
                log.warn(_("graph_output"))
                options.graph_name = None
        # check modules extra args
        if options.modules_extra_args:
            all_args = {}
            for args in options.modules_extra_args.split("&"):
                value = args.split("=")[1]
                if value.lower() == "true":
                    value = True
                elif value.lower() == "false":
                    value = False
                elif "." in value:
                    try:
                        value = float(value)
                    except Exception:
                        pass
                elif "{" in value or "[" in value:
                    try:
                        value = json.loads(value)
                    except Exception:
                        pass
                else:
                    try:
                        value = int(value)
                    except Exception:
                        pass
                all_args[args.split("=")[0]] = value
            options.modules_extra_args = all_args

        options.timeout = float(options.timeout)
        options.time_sleep_between_requests = float(options.time_sleep_between_requests)
        options.retries = int(options.retries)

        self.arguments = options
