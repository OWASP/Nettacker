"""
Extended tests for ArgParser covering more branches and validation logic.
"""

import json
import pytest
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

from nettacker.core import arg_parser as arg_module
from nettacker.core.arg_parser import ArgParser


def make_options(tmp_path, **overrides):
    """Helper to create options with defaults."""
    base = {
        "language": "en",
        "verbose_mode": False,
        "verbose_event": False,
        "show_version": False,
        "show_help_menu": False,
        "show_all_modules": False,
        "show_all_profiles": False,
        "start_api_server": False,
        "api_hostname": "0.0.0.0",
        "api_port": 5000,
        "api_debug_mode": False,
        "api_access_key": None,
        "api_client_whitelisted_ips": None,
        "api_access_log": None,
        "api_cert": None,
        "api_cert_key": None,
        "targets": "example.com",
        "targets_list": None,
        "selected_modules": "mod1",
        "profiles": None,
        "set_hardware_usage": "low",
        "thread_per_host": 1,
        "parallel_module_scan": 1,
        "excluded_modules": "",
        "ports": "80",
        "schema": "http",
        "excluded_ports": "",
        "user_agent": "custom-agent",
        "http_header": None,
        "usernames": "admin",
        "usernames_list": None,
        "passwords": "pass",
        "passwords_list": None,
        "read_from_file": None,
        "report_path_filename": str(tmp_path / "report.txt"),
        "graph_name": None,
        "modules_extra_args": None,
        "timeout": 1,
        "time_sleep_between_requests": 1,
        "retries": 1,
        "socks_proxy": None,
        "scan_compare_id": None,
        "compare_report_path_filename": str(tmp_path / "compare.txt"),
        "scan_ip_range": False,
        "scan_subdomains": False,
        "skip_service_discovery": False,
        "ping_before_scan": False,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


@pytest.fixture(autouse=True)
def stub_loaders(monkeypatch):
    """Stub test data loaders."""
    monkeypatch.setattr(ArgParser, "load_graphs", staticmethod(lambda: ["d3_tree_v1_graph", "d3_tree_v2_graph"]))
    monkeypatch.setattr(ArgParser, "load_languages", staticmethod(lambda: ["en", "fa"]))
    monkeypatch.setattr(
        ArgParser, 
        "load_modules", 
        staticmethod(lambda limit=-1, full_details=False: {
            "mod1": {"profiles": ["profile1"]},
            "mod2": {"profiles": []},
            "all": {}
        })
    )
    monkeypatch.setattr(
        ArgParser,
        "load_profiles",
        staticmethod(lambda limit=-1: {
            "profile1": ["mod1"],
            "all": []
        })
    )


class TestPortParsing:
    """Test port argument parsing."""
    
    def test_ports_single_port(self, tmp_path):
        options = make_options(tmp_path, ports="80")
        parser = ArgParser(api_arguments=options)
        assert 80 in parser.arguments.ports
    
    def test_ports_multiple_ports_comma_separated(self, tmp_path):
        options = make_options(tmp_path, ports="80,443,8080")
        parser = ArgParser(api_arguments=options)
        ports = parser.arguments.ports
        assert 80 in ports
        assert 443 in ports
        assert 8080 in ports
    
    def test_ports_range(self, tmp_path):
        options = make_options(tmp_path, ports="80-82")
        parser = ArgParser(api_arguments=options)
        ports = parser.arguments.ports
        assert 80 in ports
        assert 81 in ports
        assert 82 in ports
    
    def test_ports_mixed_single_and_range(self, tmp_path):
        options = make_options(tmp_path, ports="80,443-445")
        parser = ArgParser(api_arguments=options)
        ports = parser.arguments.ports
        assert 80 in ports
        assert 443 in ports
        assert 444 in ports
        assert 445 in ports


class TestExcludedPortsParsing:
    """Test excluded ports parsing."""
    
    def test_excluded_ports_single(self, tmp_path):
        options = make_options(tmp_path, excluded_ports="22")
        parser = ArgParser(api_arguments=options)
        assert 22 in parser.arguments.excluded_ports
    
    def test_excluded_ports_range(self, tmp_path):
        options = make_options(tmp_path, excluded_ports="1-10")
        parser = ArgParser(api_arguments=options)
        excluded = parser.arguments.excluded_ports
        assert 1 in excluded
        assert 5 in excluded
        assert 10 in excluded
    
    def test_excluded_ports_mixed(self, tmp_path):
        options = make_options(tmp_path, excluded_ports="22,23-25,443")
        parser = ArgParser(api_arguments=options)
        excluded = parser.arguments.excluded_ports
        assert 22 in excluded
        assert 23 in excluded
        assert 24 in excluded
        assert 25 in excluded
        assert 443 in excluded


class TestSchemaParsing:
    """Test schema argument parsing."""
    
    def test_schema_single_http(self, tmp_path):
        options = make_options(tmp_path, schema="http")
        parser = ArgParser(api_arguments=options)
        assert "http" in parser.arguments.schema
    
    def test_schema_multiple_comma_separated(self, tmp_path):
        options = make_options(tmp_path, schema="http,https")
        parser = ArgParser(api_arguments=options)
        schema = parser.arguments.schema
        assert "http" in schema
        assert "https" in schema


class TestModulesExtraArgsCoercion:
    """Test modules_extra_args type coercion."""
    
    def test_extra_args_boolean_true(self, tmp_path):
        options = make_options(tmp_path, modules_extra_args="enabled=true")
        parser = ArgParser(api_arguments=options)
        coerced = parser.arguments.modules_extra_args
        assert coerced["enabled"] is True
    
    def test_extra_args_boolean_false(self, tmp_path):
        options = make_options(tmp_path, modules_extra_args="enabled=false")
        parser = ArgParser(api_arguments=options)
        coerced = parser.arguments.modules_extra_args
        assert coerced["enabled"] is False
    
    def test_extra_args_integer(self, tmp_path):
        options = make_options(tmp_path, modules_extra_args="count=42")
        parser = ArgParser(api_arguments=options)
        coerced = parser.arguments.modules_extra_args
        assert coerced["count"] == 42
        assert isinstance(coerced["count"], int)
    
    def test_extra_args_float(self, tmp_path):
        options = make_options(tmp_path, modules_extra_args="ratio=3.14")
        parser = ArgParser(api_arguments=options)
        coerced = parser.arguments.modules_extra_args
        assert coerced["ratio"] == 3.14
        assert isinstance(coerced["ratio"], float)
    
    def test_extra_args_string(self, tmp_path):
        options = make_options(tmp_path, modules_extra_args="name=test")
        parser = ArgParser(api_arguments=options)
        coerced = parser.arguments.modules_extra_args
        assert coerced["name"] == "test"
    
    def test_extra_args_json_object(self, tmp_path):
        options = make_options(tmp_path, modules_extra_args='config={"key":"value"}')
        parser = ArgParser(api_arguments=options)
        coerced = parser.arguments.modules_extra_args
        assert coerced["config"] == {"key": "value"}
    
    def test_extra_args_multiple_key_value_pairs(self, tmp_path):
        options = make_options(
            tmp_path, 
            modules_extra_args="flag=true&count=5&name=test&ratio=2.5"
        )
        parser = ArgParser(api_arguments=options)
        coerced = parser.arguments.modules_extra_args
        assert coerced["flag"] is True
        assert coerced["count"] == 5
        assert coerced["name"] == "test"
        assert coerced["ratio"] == 2.5


@patch.object(arg_module, "die_failure", side_effect=RuntimeError("fail"))
class TestValidationFailures:
    """Test validation error conditions."""
    
    def test_invalid_language_fails(self, mock_die, tmp_path):
        options = make_options(tmp_path, language="invalid_lang")
        with pytest.raises(RuntimeError, match="fail"):
            ArgParser(api_arguments=options)
        mock_die.assert_called()
    
    def test_invalid_graph_fails(self, mock_die, tmp_path):
        options = make_options(tmp_path, graph_name="nonexistent_graph")
        with pytest.raises(RuntimeError, match="fail"):
            ArgParser(api_arguments=options)
        mock_die.assert_called()
    
    def test_invalid_schema_fails(self, mock_die, tmp_path):
        options = make_options(tmp_path, schema="invalid_schema")
        with pytest.raises(RuntimeError, match="fail"):
            ArgParser(api_arguments=options)
        mock_die.assert_called()
    
    def test_invalid_hardware_usage_fails(self, mock_die, tmp_path):
        options = make_options(tmp_path, set_hardware_usage="ultra")
        with pytest.raises(RuntimeError, match="fail"):
            ArgParser(api_arguments=options)
        mock_die.assert_called()


class TestThreadingOptions:
    """Test threading and module scan options."""
    
    def test_thread_per_host_minimum_enforced(self, tmp_path):
        options = make_options(tmp_path, thread_per_host=0)
        parser = ArgParser(api_arguments=options)
        # Should be bumped to 1
        assert parser.arguments.thread_per_host >= 1
    
    def test_thread_per_host_valid_value(self, tmp_path):
        options = make_options(tmp_path, thread_per_host=4)
        parser = ArgParser(api_arguments=options)
        assert parser.arguments.thread_per_host == 4
    
    def test_parallel_module_scan_minimum_enforced(self, tmp_path):
        options = make_options(tmp_path, parallel_module_scan=-1)
        parser = ArgParser(api_arguments=options)
        # Should be bumped to 1
        assert parser.arguments.parallel_module_scan >= 1
    
    def test_parallel_module_scan_valid_value(self, tmp_path):
        options = make_options(tmp_path, parallel_module_scan=2)
        parser = ArgParser(api_arguments=options)
        assert parser.arguments.parallel_module_scan == 2


class TestModuleSelection:
    """Test module and profile selection logic."""
    
    def test_module_selection_single(self, tmp_path):
        options = make_options(tmp_path, selected_modules="mod1")
        parser = ArgParser(api_arguments=options)
        assert "mod1" in parser.arguments.selected_modules
    
    def test_module_selection_multiple(self, tmp_path):
        options = make_options(tmp_path, selected_modules="mod1,mod2")
        parser = ArgParser(api_arguments=options)
        modules = parser.arguments.selected_modules
        assert "mod1" in modules
        assert "mod2" in modules
    
    @patch.object(arg_module, "die_failure", side_effect=RuntimeError("module_not_found"))
    def test_invalid_module_name_fails(self, mock_die, tmp_path):
        options = make_options(tmp_path, selected_modules="invalid_module")
        with pytest.raises(RuntimeError, match="module_not_found"):
            ArgParser(api_arguments=options)
    
    def test_profile_selection(self, tmp_path):
        options = make_options(tmp_path, profiles="profile1", selected_modules="")
        parser = ArgParser(api_arguments=options)
        # Modules from profile should be selected
        assert len(parser.arguments.selected_modules) > 0


class TestHardwareUsageOptions:
    """Test hardware usage configuration."""
    
    def test_hardware_usage_low(self, tmp_path):
        options = make_options(tmp_path, set_hardware_usage="low")
        parser = ArgParser(api_arguments=options)
        # Should be parsed to a numeric value
        assert isinstance(parser.arguments.set_hardware_usage, int)
    
    def test_hardware_usage_normal(self, tmp_path):
        options = make_options(tmp_path, set_hardware_usage="normal")
        parser = ArgParser(api_arguments=options)
        assert isinstance(parser.arguments.set_hardware_usage, int)
    
    def test_hardware_usage_high(self, tmp_path):
        options = make_options(tmp_path, set_hardware_usage="high")
        parser = ArgParser(api_arguments=options)
        assert isinstance(parser.arguments.set_hardware_usage, int)
    
    def test_hardware_usage_maximum(self, tmp_path):
        options = make_options(tmp_path, set_hardware_usage="maximum")
        parser = ArgParser(api_arguments=options)
        assert isinstance(parser.arguments.set_hardware_usage, int)


class TestTimeoutOptions:
    """Test timeout configuration."""
    
    def test_timeout_float_value(self, tmp_path):
        options = make_options(tmp_path, timeout=5.5)
        parser = ArgParser(api_arguments=options)
        assert parser.arguments.timeout == 5.5
    
    def test_time_sleep_float_value(self, tmp_path):
        options = make_options(tmp_path, time_sleep_between_requests=0.5)
        parser = ArgParser(api_arguments=options)
        assert parser.arguments.time_sleep_between_requests == 0.5


class TestRetryOptions:
    """Test retry configuration."""
    
    def test_retries_integer(self, tmp_path):
        options = make_options(tmp_path, retries=3)
        parser = ArgParser(api_arguments=options)
        assert parser.arguments.retries == 3


class TestBooleanFlags:
    """Test boolean flag options."""
    
    def test_scan_ip_range_flag(self, tmp_path):
        options = make_options(tmp_path, scan_ip_range=True)
        parser = ArgParser(api_arguments=options)
        assert parser.arguments.scan_ip_range is True
    
    def test_scan_subdomains_flag(self, tmp_path):
        options = make_options(tmp_path, scan_subdomains=True)
        parser = ArgParser(api_arguments=options)
        assert parser.arguments.scan_subdomains is True
    
    def test_skip_service_discovery_flag(self, tmp_path):
        options = make_options(tmp_path, skip_service_discovery=True)
        parser = ArgParser(api_arguments=options)
        assert parser.arguments.skip_service_discovery is True
    
    def test_ping_before_scan_flag(self, tmp_path):
        options = make_options(tmp_path, ping_before_scan=True)
        parser = ArgParser(api_arguments=options)
        assert parser.arguments.ping_before_scan is True


class TestApiOptions:
    """Test API configuration options."""
    
    def test_api_hostname(self, tmp_path):
        options = make_options(tmp_path, api_hostname="127.0.0.1")
        parser = ArgParser(api_arguments=options)
        assert parser.arguments.api_hostname == "127.0.0.1"
    
    def test_api_port(self, tmp_path):
        options = make_options(tmp_path, api_port=8000)
        parser = ArgParser(api_arguments=options)
        assert parser.arguments.api_port == 8000
    
    def test_api_debug_mode(self, tmp_path):
        options = make_options(tmp_path, api_debug_mode=True)
        parser = ArgParser(api_arguments=options)
        assert parser.arguments.api_debug_mode is True
    
    def test_api_access_key(self, tmp_path):
        options = make_options(tmp_path, api_access_key="test_key_123")
        parser = ArgParser(api_arguments=options)
        assert parser.arguments.api_access_key == "test_key_123"


class TestSocksProxyOption:
    """Test SOCKS proxy configuration."""
    
    def test_socks_proxy(self, tmp_path):
        options = make_options(tmp_path, socks_proxy="127.0.0.1:9050")
        parser = ArgParser(api_arguments=options)
        assert parser.arguments.socks_proxy == "127.0.0.1:9050"
