import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from nettacker.core import arg_parser as arg_module
from nettacker.core.arg_parser import ArgParser


def make_options(tmp_path, **overrides):
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
    monkeypatch.setattr(ArgParser, "load_graphs", staticmethod(lambda: ["g1", "g2"]))
    monkeypatch.setattr(ArgParser, "load_languages", staticmethod(lambda: ["en", "fr"]))
    monkeypatch.setattr(ArgParser, "load_modules", staticmethod(lambda limit=-1, full_details=False: {"mod1": {"profiles": []}, "all": {}}))
    monkeypatch.setattr(ArgParser, "load_profiles", staticmethod(lambda limit=-1: {"all": []}))


@patch.object(arg_module, "die_failure", side_effect=RuntimeError("fail"))
def test_invalid_language_triggers_die_failure(mock_die, tmp_path):
    options = make_options(tmp_path, language="de")
    with pytest.raises(RuntimeError):
        ArgParser(api_arguments=options)
    mock_die.assert_called_once()


@patch.object(arg_module, "die_failure", side_effect=RuntimeError("invalid-graph"))
def test_invalid_graph_name(mock_die, tmp_path):
    options = make_options(tmp_path, graph_name="missing")
    with pytest.raises(RuntimeError):
        ArgParser(api_arguments=options)
    mock_die.assert_called_once()


def test_excluded_ports_range_parsed(tmp_path):
    options = make_options(tmp_path, excluded_ports="1-2,5")
    parser = ArgParser(api_arguments=options)
    assert sorted(parser.arguments.excluded_ports) == [1, 2, 5]


def test_modules_extra_args_are_coerced(tmp_path):
    raw_args = "flag=true&count=2&pi=3.1&obj={\"a\":1}"
    options = make_options(tmp_path, modules_extra_args=raw_args)
    parser = ArgParser(api_arguments=options)
    coerced = parser.arguments.modules_extra_args
    assert coerced == {"flag": True, "count": 2, "pi": 3.1, "obj": {"a": 1}}


@patch.object(arg_module, "die_failure", side_effect=RuntimeError("bad-schema"))
def test_invalid_schema(mock_die, tmp_path):
    options = make_options(tmp_path, schema="ftp")
    with pytest.raises(RuntimeError):
        ArgParser(api_arguments=options)
    mock_die.assert_called_once()
