"""
Tests for nettacker/core/app.py - Core scan engine and orchestration
"""

import os
from unittest.mock import Mock, patch

from nettacker.core.app import Nettacker


class TestNettackerInit:
    """Test Nettacker initialization"""

    @patch("nettacker.core.app.ArgParser.__init__")
    @patch.object(Nettacker, "print_logo")
    @patch.object(Nettacker, "check_dependencies")
    def test_init_without_api_arguments(self, mock_check_deps, mock_logo, mock_arg_parser):
        """Test initialization without API arguments prints logo"""
        mock_arg_parser.return_value = None

        Nettacker()

        mock_logo.assert_called_once()
        mock_check_deps.assert_called_once()

    @patch("nettacker.core.app.ArgParser.__init__")
    @patch.object(Nettacker, "print_logo")
    @patch.object(Nettacker, "check_dependencies")
    def test_init_with_api_arguments(self, mock_check_deps, mock_logo, mock_arg_parser):
        """Test initialization with API arguments doesn't print logo"""
        mock_arg_parser.return_value = None
        api_args = {"targets": ["127.0.0.1"]}

        Nettacker(api_arguments=api_args)

        mock_logo.assert_not_called()
        mock_check_deps.assert_called_once()


class TestExpandTargets:
    """Test target expansion and processing"""

    @patch("nettacker.core.app.ArgParser.__init__")
    @patch.object(Nettacker, "print_logo")
    @patch.object(Nettacker, "check_dependencies")
    def test_expand_single_ipv4(self, mock_check_deps, mock_logo, mock_arg_parser):
        """Test expansion of single IPv4 address"""
        mock_arg_parser.return_value = None
        scanner = Nettacker(api_arguments={})
        scanner.arguments = Mock()
        scanner.arguments.targets = ["192.168.1.1"]
        scanner.arguments.scan_ip_range = False
        scanner.arguments.scan_subdomains = False
        scanner.arguments.ping_before_scan = False
        scanner.arguments.skip_service_discovery = True

        result = scanner.expand_targets("test_scan_id")

        assert result == ["192.168.1.1"]

    @patch("nettacker.core.app.ArgParser.__init__")
    @patch.object(Nettacker, "print_logo")
    @patch.object(Nettacker, "check_dependencies")
    @patch("nettacker.core.app.generate_ip_range")
    def test_expand_cidr_range(
        self, mock_generate_ip, mock_check_deps, mock_logo, mock_arg_parser
    ):
        """Test expansion of CIDR range"""
        mock_arg_parser.return_value = None
        mock_generate_ip.return_value = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]

        scanner = Nettacker(api_arguments={})
        scanner.arguments = Mock()
        scanner.arguments.targets = ["192.168.1.0/30"]
        scanner.arguments.scan_subdomains = False
        scanner.arguments.ping_before_scan = False
        scanner.arguments.skip_service_discovery = True

        result = scanner.expand_targets("test_scan_id")

        mock_generate_ip.assert_called_once_with("192.168.1.0/30")
        assert set(result) == {"192.168.1.1", "192.168.1.2", "192.168.1.3"}

    @patch("nettacker.core.app.ArgParser.__init__")
    @patch.object(Nettacker, "print_logo")
    @patch.object(Nettacker, "check_dependencies")
    def test_expand_url_with_path(self, mock_check_deps, mock_logo, mock_arg_parser):
        """Test expansion of URL with base path extraction"""
        mock_arg_parser.return_value = None
        scanner = Nettacker(api_arguments={})
        scanner.arguments = Mock()
        scanner.arguments.targets = ["http://example.com/admin/panel"]
        scanner.arguments.scan_ip_range = False
        scanner.arguments.scan_subdomains = False
        scanner.arguments.ping_before_scan = False
        scanner.arguments.skip_service_discovery = True

        result = scanner.expand_targets("test_scan_id")

        assert result == ["example.com"]
        assert scanner.arguments.url_base_path == "admin/panel/"

    @patch("nettacker.core.app.ArgParser.__init__")
    @patch.object(Nettacker, "print_logo")
    @patch.object(Nettacker, "check_dependencies")
    def test_expand_domain(self, mock_check_deps, mock_logo, mock_arg_parser):
        """Test expansion of domain name"""
        mock_arg_parser.return_value = None
        scanner = Nettacker(api_arguments={})
        scanner.arguments = Mock()
        scanner.arguments.targets = ["example.com"]
        scanner.arguments.scan_ip_range = False
        scanner.arguments.scan_subdomains = False
        scanner.arguments.ping_before_scan = False
        scanner.arguments.skip_service_discovery = True

        result = scanner.expand_targets("test_scan_id")

        assert result == ["example.com"]


class TestScanTargetGroup:
    """Test multi-threaded target group scanning"""

    @patch("nettacker.core.app.ArgParser.__init__")
    @patch.object(Nettacker, "print_logo")
    @patch.object(Nettacker, "check_dependencies")
    @patch("nettacker.core.app.wait_for_threads_to_finish")
    @patch("nettacker.core.app.Thread")
    def test_scan_target_group_single_target(
        self, mock_thread, mock_wait, mock_check_deps, mock_logo, mock_arg_parser
    ):
        """Test scanning a single target with one module"""
        mock_arg_parser.return_value = None
        mock_wait.return_value = True
        mock_thread_instance = Mock()
        mock_thread.return_value = mock_thread_instance

        scanner = Nettacker(api_arguments={})
        scanner.arguments = Mock()
        scanner.arguments.selected_modules = ["port_scan"]
        scanner.arguments.parallel_module_scan = 10

        result = scanner.scan_target_group(["192.168.1.1"], "test_scan_id", 0)

        assert result is True
        mock_thread.assert_called_once()
        mock_thread_instance.start.assert_called_once()

    @patch("nettacker.core.app.ArgParser.__init__")
    @patch.object(Nettacker, "print_logo")
    @patch.object(Nettacker, "check_dependencies")
    @patch("nettacker.core.app.wait_for_threads_to_finish")
    @patch("nettacker.core.app.Thread")
    def test_scan_target_group_multiple_targets_modules(
        self, mock_thread, mock_wait, mock_check_deps, mock_logo, mock_arg_parser
    ):
        """Test scanning multiple targets with multiple modules"""
        mock_arg_parser.return_value = None
        mock_wait.return_value = True
        mock_thread_instance = Mock()
        mock_thread.return_value = mock_thread_instance

        scanner = Nettacker(api_arguments={})
        scanner.arguments = Mock()
        scanner.arguments.selected_modules = ["port_scan", "subdomain_scan"]
        scanner.arguments.parallel_module_scan = 10

        targets = ["192.168.1.1", "192.168.1.2"]
        result = scanner.scan_target_group(targets, "test_scan_id", 0)

        assert result is True
        # 2 targets * 2 modules = 4 threads
        assert mock_thread.call_count == 4
        assert mock_thread_instance.start.call_count == 4


class TestScanTarget:
    """Test individual target scanning"""

    @patch("nettacker.core.app.ArgParser.__init__")
    @patch.object(Nettacker, "print_logo")
    @patch.object(Nettacker, "check_dependencies")
    @patch("nettacker.core.app.socket.socket")
    @patch("nettacker.core.app.socket.getaddrinfo")
    @patch("nettacker.core.app.set_socks_proxy")
    @patch("nettacker.core.app.Module")
    def test_scan_target_success(
        self,
        mock_module_class,
        mock_socks,
        mock_getaddrinfo,
        mock_socket_class,
        mock_check_deps,
        mock_logo,
        mock_arg_parser,
    ):
        """Test successful single target scan"""
        mock_arg_parser.return_value = None
        mock_module = Mock()
        mock_module_class.return_value = mock_module
        # set_socks_proxy returns original socket funcs for restoration
        original_socket = Mock()
        original_getaddrinfo = Mock()
        mock_socks.return_value = (original_socket, original_getaddrinfo)

        scanner = Nettacker(api_arguments={})
        scanner.arguments = Mock()
        scanner.arguments.socks_proxy = None

        result = scanner.scan_target(
            target="192.168.1.1",
            module_name="port_scan",
            scan_id="test_scan_id",
            process_number=1,
            thread_number=1,
            total_number_threads=10,
        )

        assert result == os.EX_OK
        mock_module.load.assert_called_once()
        mock_module.generate_loops.assert_called_once()
        mock_module.sort_loops.assert_called_once()
        mock_module.start.assert_called_once()


class TestStartScan:
    """Test scan initialization and process management"""

    @patch("nettacker.core.app.ArgParser.__init__")
    @patch.object(Nettacker, "print_logo")
    @patch.object(Nettacker, "check_dependencies")
    @patch("nettacker.core.app.common_utils.generate_target_groups")
    @patch("nettacker.core.app.remove_old_logs")
    @patch("nettacker.core.app.multiprocess.Process")
    @patch("nettacker.core.app.wait_for_threads_to_finish")
    def test_start_scan_single_process(
        self,
        mock_wait,
        mock_process_class,
        mock_remove_logs,
        mock_generate_groups,
        mock_check_deps,
        mock_logo,
        mock_arg_parser,
    ):
        """Test starting scan with single process"""
        mock_arg_parser.return_value = None
        mock_generate_groups.return_value = [["192.168.1.1"]]
        mock_process = Mock()
        mock_process_class.return_value = mock_process
        mock_wait.return_value = True

        scanner = Nettacker(api_arguments={})
        scanner.arguments = Mock()
        scanner.arguments.targets = ["192.168.1.1"]
        scanner.arguments.selected_modules = ["port_scan"]
        scanner.arguments.set_hardware_usage = "normal"
        scanner.arguments.scan_compare_id = None

        result = scanner.start_scan("test_scan_id")

        assert result is True
        mock_process_class.assert_called_once()
        mock_process.start.assert_called_once()
        mock_remove_logs.assert_called()

    @patch("nettacker.core.app.ArgParser.__init__")
    @patch.object(Nettacker, "print_logo")
    @patch.object(Nettacker, "check_dependencies")
    @patch("nettacker.core.app.common_utils.generate_target_groups")
    @patch("nettacker.core.app.remove_old_logs")
    @patch("nettacker.core.app.multiprocess.Process")
    @patch("nettacker.core.app.wait_for_threads_to_finish")
    def test_start_scan_multiple_processes(
        self,
        mock_wait,
        mock_process_class,
        mock_remove_logs,
        mock_generate_groups,
        mock_check_deps,
        mock_logo,
        mock_arg_parser,
    ):
        """Test starting scan with multiple processes"""
        mock_arg_parser.return_value = None
        mock_generate_groups.return_value = [["192.168.1.1"], ["192.168.1.2"], ["192.168.1.3"]]
        mock_process = Mock()
        mock_process_class.return_value = mock_process
        mock_wait.return_value = True

        scanner = Nettacker(api_arguments={})
        scanner.arguments = Mock()
        scanner.arguments.targets = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
        scanner.arguments.selected_modules = ["port_scan"]
        scanner.arguments.set_hardware_usage = "high"
        scanner.arguments.scan_compare_id = None

        result = scanner.start_scan("test_scan_id")

        assert result is True
        assert mock_process_class.call_count == 3
        assert mock_process.start.call_count == 3


class TestFilterTargetByEvent:
    """Test target filtering based on events"""

    @patch("nettacker.core.app.ArgParser.__init__")
    @patch.object(Nettacker, "print_logo")
    @patch.object(Nettacker, "check_dependencies")
    @patch("nettacker.core.app.find_events")
    def test_filter_target_with_events(
        self, mock_find_events, mock_check_deps, mock_logo, mock_arg_parser
    ):
        """Test filtering targets that have events"""
        mock_arg_parser.return_value = None
        mock_find_events.side_effect = lambda target, module, scan_id: (
            [Mock()] if target == "192.168.1.1" else []
        )

        scanner = Nettacker(api_arguments={})
        targets = ["192.168.1.1", "192.168.1.2"]

        result = scanner.filter_target_by_event(targets, "test_scan_id", "port_scan")

        assert result == ["192.168.1.1"]

    @patch("nettacker.core.app.ArgParser.__init__")
    @patch.object(Nettacker, "print_logo")
    @patch.object(Nettacker, "check_dependencies")
    @patch("nettacker.core.app.find_events")
    def test_filter_target_no_events(
        self, mock_find_events, mock_check_deps, mock_logo, mock_arg_parser
    ):
        """Test filtering targets with no events"""
        mock_arg_parser.return_value = None
        mock_find_events.return_value = []

        scanner = Nettacker(api_arguments={})
        targets = ["192.168.1.1", "192.168.1.2"]

        result = scanner.filter_target_by_event(targets, "test_scan_id", "port_scan")

        assert result == []


class TestRun:
    """Test main scan orchestration"""

    @patch("nettacker.core.app.ArgParser.__init__")
    @patch.object(Nettacker, "print_logo")
    @patch.object(Nettacker, "check_dependencies")
    @patch("nettacker.core.app.common_utils.generate_random_token")
    @patch.object(Nettacker, "expand_targets")
    @patch.object(Nettacker, "start_scan")
    @patch("nettacker.core.app.create_report")
    def test_run_success(
        self,
        mock_create_report,
        mock_start_scan,
        mock_expand,
        mock_token,
        mock_check_deps,
        mock_logo,
        mock_arg_parser,
    ):
        """Test successful scan run"""
        mock_arg_parser.return_value = None
        mock_token.return_value = "scan123"
        mock_expand.return_value = ["192.168.1.1"]
        mock_start_scan.return_value = True

        scanner = Nettacker(api_arguments={})
        scanner.arguments = Mock()
        scanner.arguments.scan_compare_id = None

        result = scanner.run()

        assert result is True
        mock_create_report.assert_called_once()

    @patch("nettacker.core.app.ArgParser.__init__")
    @patch.object(Nettacker, "print_logo")
    @patch.object(Nettacker, "check_dependencies")
    @patch("nettacker.core.app.common_utils.generate_random_token")
    @patch.object(Nettacker, "expand_targets")
    def test_run_no_targets(
        self, mock_expand, mock_token, mock_check_deps, mock_logo, mock_arg_parser
    ):
        """Test scan run with no targets after expansion"""
        mock_arg_parser.return_value = None
        mock_token.return_value = "scan123"
        mock_expand.return_value = []

        scanner = Nettacker(api_arguments={})
        scanner.arguments = Mock()

        result = scanner.run()

        assert result is True

    @patch("nettacker.core.app.ArgParser.__init__")
    @patch.object(Nettacker, "print_logo")
    @patch.object(Nettacker, "check_dependencies")
    @patch("nettacker.core.app.common_utils.generate_random_token")
    @patch.object(Nettacker, "expand_targets")
    @patch.object(Nettacker, "start_scan")
    @patch("nettacker.core.app.create_report")
    @patch("nettacker.core.app.create_compare_report")
    def test_run_with_compare(
        self,
        mock_compare_report,
        mock_create_report,
        mock_start_scan,
        mock_expand,
        mock_token,
        mock_check_deps,
        mock_logo,
        mock_arg_parser,
    ):
        """Test scan run with comparison report"""
        mock_arg_parser.return_value = None
        mock_token.return_value = "scan123"
        mock_expand.return_value = ["192.168.1.1"]
        mock_start_scan.return_value = True

        scanner = Nettacker(api_arguments={})
        scanner.arguments = Mock()
        scanner.arguments.scan_compare_id = "previous_scan"

        result = scanner.run()

        assert result is True
        mock_create_report.assert_called_once()
        mock_compare_report.assert_called_once()
