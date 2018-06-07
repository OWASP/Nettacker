from canari.maltego.entities import Unknown
from canari.maltego.transform import Transform
from canari.framework import EnableDebugWindow
from common.entities import NettackerScan

from core.config_builder import _core_default_config, _builder
from core.config import _core_config
from core.attack import __go_for_attacks

from database.db import __logs_by_scan_id


__author__ = 'Shaddy Garg'
__copyright__ = 'Copyright 2018, nettacker_transforms Project'
__credits__ = []

__license__ = 'GPLv3'
__version__ = '0.1'
__maintainer__ = 'Shaddy Garg'
__email__ = 'shaddygarg1@gmail.com'
__status__ = 'Development'


@EnableDebugWindow
class PortScan(Transform):
    """TODO: Your transform description."""

    # The transform input entity type.
    input_type = NettackerScan

    def do_transform(self, request, response, config):
        # TODO: write your code here.
        _start_scan_config = {}
        scan_request = request.entity
        _start_scan_config["targets"] = scan_request.host
        _start_scan_config["ports"] = scan_request.ports
        _start_scan_config["retries"] = scan_request.retries
        _start_scan_config["verbose"] = scan_request.verbose
        _start_scan_config["timeout_sec"] = scan_request.timeout_sec
        _start_scan_config["socks_proxy"] = scan_request.socks_proxy
        _start_scan_config["thread_number"] = scan_request.thread_no
        config = _builder(_start_scan_config, _builder(_core_config(), _core_default_config()))
        targets = config["targets"]
        check_ranges = config["check_ranges"]
        check_subdomains = config["check_subdomains"]
        log_in_file = config["log_in_file"]
        time_sleep = config["time_sleep"]
        language = config["language"]
        verbose_level = config["verbose_level"]
        retries = config["retries"]
        socks_proxy = config["socks_proxy"]
        scan_method = "port_scan"
        users = config["users"]
        passwds = config["passwds"]
        timeout_sec = config["timeout_sec"]
        thread_number = config["thread_number"]
        ports = config["ports"]
        ping_flag = config["ping_flag"]
        methods_args = config["methods_args"]
        thread_number_host = config["thread_number_host"]
        graph_flag = config["graph_flag"]
        profile = config["profile"]
        backup_ports = config["backup_ports"]
        result = __go_for_attacks(targets, check_ranges, check_subdomains, log_in_file, time_sleep, language,
                                  verbose_level,retries,socks_proxy, users, passwds, timeout_sec, thread_number,
                                  ports, ping_flag, methods_args, backup_ports, scan_method, thread_number_host,
                                  graph_flag, profile, True, scan_id="123456789")
        re = __logs_by_scan_id("123456789", "en")
        print re
        return response

    def on_terminate(self):
        """This method gets called when transform execution is prematurely terminated. It is only applicable for local
        transforms. It can be excluded if you don't need it."""
        pass