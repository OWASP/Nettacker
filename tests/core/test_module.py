"""
Tests for nettacker/core/module.py - Module orchestration and execution
"""
import copy
import json
from unittest.mock import Mock, MagicMock, patch, call

import pytest

from nettacker.core.module import Module


class TestModuleInit:
    """Test Module initialization"""

    @patch("nettacker.core.module.TemplateLoader")
    def test_module_initialization(self, mock_template_loader):
        """Test basic module initialization"""
        mock_template_loader.return_value.load.return_value = {
            "payloads": [{"steps": [{"response": {"conditions": {}}}]}]
        }

        options = Mock()
        options.__dict__ = {
            "modules_extra_args": None,
            "skip_service_discovery": False,
        }

        module = Module(
            module_name="port_scan",
            options=options,
            target="192.168.1.1",
            scan_id="test_scan",
            process_number=1,
            thread_number=1,
            total_number_threads=10,
        )

        assert module.module_name == "port_scan"
        assert module.target == "192.168.1.1"
        assert module.scan_id == "test_scan"
        assert module.process_number == 1

    @patch("nettacker.core.module.TemplateLoader")
    def test_module_with_extra_args(self, mock_template_loader):
        """Test module initialization with extra arguments"""
        mock_template_loader.return_value.load.return_value = {
            "payloads": [{"steps": [{"response": {"conditions": {}}}]}]
        }

        options = Mock()
        options.__dict__ = {
            "modules_extra_args": {"custom_header": "test_value"},
            "skip_service_discovery": False,
        }

        module = Module(
            module_name="vuln_scan",
            options=options,
            target="example.com",
            scan_id="test_scan",
            process_number=1,
            thread_number=1,
            total_number_threads=10,
        )

        assert module.module_inputs["custom_header"] == "test_value"


class TestModuleLoad:
    """Test module loading and service discovery"""

    @patch("nettacker.core.module.TemplateLoader")
    @patch("nettacker.core.module.find_events")
    def test_load_without_service_discovery(self, mock_find_events, mock_template_loader):
        """Test loading module without service discovery"""
        mock_template_loader.return_value.load.return_value = {
            "payloads": [
                {"library": "http", "steps": [{"request": {}, "response": {}}]}
            ]
        }

        options = Mock()
        options.__dict__ = {"modules_extra_args": None, "skip_service_discovery": True}

        module = Module(
            module_name="port_scan",
            options=options,
            target="192.168.1.1",
            scan_id="test_scan",
            process_number=1,
            thread_number=1,
            total_number_threads=10,
        )
        module.skip_service_discovery = True

        module.load()

        mock_find_events.assert_not_called()
        assert module.module_content is not None

    @patch("nettacker.core.module.TemplateLoader")
    @patch("nettacker.core.module.find_events")
    @patch("nettacker.core.module.os.listdir")
    def test_load_with_service_discovery(
        self, mock_listdir, mock_find_events, mock_template_loader
    ):
        """Test loading module with service discovery"""
        mock_listdir.return_value = ["http.py", "ssh.py", "__init__.py"]
        
        # Mock template loader for initialization
        init_template_mock = Mock()
        init_template_mock.load.return_value = {
            "payloads": [
                {
                    "steps": [
                        {
                            "response": {
                                "conditions": {
                                    "service": {"http": {}, "ssh": {}}
                                }
                            }
                        }
                    ]
                }
            ]
        }
        
        # Mock template loader for actual module load
        load_template_mock = Mock()
        load_template_mock.load.return_value = {
            "payloads": [
                {
                    "library": "http",
                    "steps": [{"port": [], "request": {}, "response": {}}]
                }
            ]
        }
        
        # Setup template loader to return different mocks
        mock_template_loader.side_effect = [init_template_mock, load_template_mock]

        # Mock service discovery
        mock_event = Mock()
        mock_event.json_event = json.dumps({
            "port": 80,
            "response": {"conditions_results": {"http": {}}}
        })
        mock_find_events.return_value = [mock_event]

        options = Mock()
        options.__dict__ = {"modules_extra_args": None, "skip_service_discovery": False}

        module = Module(
            module_name="http_vuln",
            options=options,
            target="192.168.1.1",
            scan_id="test_scan",
            process_number=1,
            thread_number=1,
            total_number_threads=10,
        )
        module.skip_service_discovery = False
        module.ignored_core_modules = ["port_scan", "icmp_scan"]

        module.load()

        mock_find_events.assert_called_with("192.168.1.1", "port_scan", "test_scan")
        assert module.discovered_services == {"http": [80]}


class TestGenerateLoops:
    """Test module loop generation"""

    @patch("nettacker.core.module.TemplateLoader")
    @patch("nettacker.core.module.expand_module_steps")
    def test_generate_loops_basic(self, mock_expand, mock_template_loader):
        """Test basic loop generation"""
        mock_template_loader.return_value.load.return_value = {
            "payloads": [{"steps": [{"response": {"conditions": {}}}]}]
        }
        mock_expand.return_value = [
            {"library": "http", "steps": [{"request": {}}]}
        ]

        options = Mock()
        options.__dict__ = {
            "modules_extra_args": None,
            "skip_service_discovery": True,
            "excluded_ports": None,
        }

        module = Module(
            module_name="port_scan",
            options=options,
            target="192.168.1.1",
            scan_id="test_scan",
            process_number=1,
            thread_number=1,
            total_number_threads=10,
        )
        module.module_content = {
            "payloads": [{"library": "http", "steps": [{"request": {}}]}]
        }

        module.generate_loops()

        mock_expand.assert_called_once()

    @patch("nettacker.core.module.TemplateLoader")
    @patch("nettacker.core.module.expand_module_steps")
    def test_generate_loops_with_excluded_ports(self, mock_expand, mock_template_loader):
        """Test loop generation with excluded ports"""
        mock_template_loader.return_value.load.return_value = {
            "payloads": [{"steps": [{"response": {"conditions": {}}}]}]
        }
        mock_expand.return_value = [
            {"library": "http", "steps": [{"ports": [80, 443, 8080]}]}
        ]

        options = Mock()
        options.__dict__ = {
            "modules_extra_args": None,
            "skip_service_discovery": True,
            "excluded_ports": [443],
        }

        module = Module(
            module_name="port_scan",
            options=options,
            target="192.168.1.1",
            scan_id="test_scan",
            process_number=1,
            thread_number=1,
            total_number_threads=10,
        )
        module.module_content = {
            "payloads": [{"library": "http", "steps": [{"ports": [80, 443, 8080]}]}]
        }
        module.module_inputs["excluded_ports"] = [443]

        module.generate_loops()

        # Port 443 should be excluded
        assert 443 not in module.module_content["payloads"][0]["steps"][0]["ports"]
        assert 80 in module.module_content["payloads"][0]["steps"][0]["ports"]


class TestSortLoops:
    """Test module loop sorting by dependencies"""

    @patch("nettacker.core.module.TemplateLoader")
    def test_sort_loops_no_dependencies(self, mock_template_loader):
        """Test sorting loops without dependencies"""
        mock_template_loader.return_value.load.return_value = {
            "payloads": [{"steps": [{"response": {"conditions": {}}}]}]
        }

        options = Mock()
        options.__dict__ = {
            "modules_extra_args": None,
            "skip_service_discovery": True,
        }

        module = Module(
            module_name="port_scan",
            options=options,
            target="192.168.1.1",
            scan_id="test_scan",
            process_number=1,
            thread_number=1,
            total_number_threads=10,
        )

        # Steps without dependencies
        module.module_content = {
            "payloads": [
                {
                    "steps": [
                        [{"response": {}}],
                        [{"response": {}}],
                    ]
                }
            ]
        }

        module.sort_loops()

        # All steps should remain in order
        assert len(module.module_content["payloads"][0]["steps"]) == 2

    @patch("nettacker.core.module.TemplateLoader")
    def test_sort_loops_with_dependencies(self, mock_template_loader):
        """Test sorting loops with temp and normal dependencies"""
        mock_template_loader.return_value.load.return_value = {
            "payloads": [{"steps": [{"response": {"conditions": {}}}]}]
        }

        options = Mock()
        options.__dict__ = {
            "modules_extra_args": None,
            "skip_service_discovery": True,
        }

        module = Module(
            module_name="vuln_scan",
            options=options,
            target="192.168.1.1",
            scan_id="test_scan",
            process_number=1,
            thread_number=1,
            total_number_threads=10,
        )

        # Steps with different dependencies
        module.module_content = {
            "payloads": [
                {
                    "steps": [
                        [{"response": {"dependent_on_temp_event": True}}],  # Normal dependency
                        [{"response": {}}],  # No dependency
                        [{"response": {"dependent_on_temp_event": True, "save_to_temp_events_only": True}}],  # Temp dependency
                    ]
                }
            ]
        }

        module.sort_loops()

        steps = module.module_content["payloads"][0]["steps"]
        # Order should be: no deps, temp deps, normal deps
        assert "dependent_on_temp_event" not in steps[0][0]["response"]
        assert "save_to_temp_events_only" in steps[1][0]["response"]
        assert "save_to_temp_events_only" not in steps[2][0]["response"]


class TestModuleStart:
    """Test module execution"""

    @patch("nettacker.core.module.TemplateLoader")
    @patch("nettacker.core.module.importlib.import_module")
    @patch("nettacker.core.module.Thread")
    @patch("nettacker.core.module.wait_for_threads_to_finish")
    def test_start_single_payload(
        self, mock_wait, mock_thread, mock_import, mock_template_loader
    ):
        """Test starting module with single payload"""
        mock_template_loader.return_value.load.return_value = {
            "payloads": [{"steps": [{"response": {"conditions": {}}}]}]
        }

        # Mock the engine
        mock_engine = Mock()
        mock_import.return_value.HttpEngine.return_value = mock_engine

        mock_thread_instance = Mock()
        mock_thread.return_value = mock_thread_instance
        mock_wait.return_value = True

        options = Mock()
        options.__dict__ = {
            "modules_extra_args": None,
            "skip_service_discovery": True,
            "parallel_module_scan": 10,
            "thread_per_host": 10,
            "time_sleep_between_requests": 0,
        }

        module = Module(
            module_name="port_scan",
            options=options,
            target="192.168.1.1",
            scan_id="test_scan",
            process_number=1,
            thread_number=1,
            total_number_threads=10,
        )

        module.module_content = {
            "payloads": [
                {
                    "library": "http",
                    "steps": [[{"request": {}, "response": {}}]]
                }
            ]
        }
        module.libraries = ["http", "ssh", "ftp"]

        module.start()

        mock_thread.assert_called_once()
        mock_thread_instance.start.assert_called_once()
        mock_engine.run.assert_not_called()  # Called in thread, not directly

    @patch("nettacker.core.module.TemplateLoader")
    @patch("nettacker.core.module.importlib.import_module")
    @patch("nettacker.core.module.Thread")
    @patch("nettacker.core.module.wait_for_threads_to_finish")
    def test_start_multiple_payloads(
        self, mock_wait, mock_thread, mock_import, mock_template_loader
    ):
        """Test starting module with multiple payloads"""
        mock_template_loader.return_value.load.return_value = {
            "payloads": [{"steps": [{"response": {"conditions": {}}}]}]
        }

        # Mock the engine
        mock_engine = Mock()
        mock_import.return_value.HttpEngine.return_value = mock_engine

        mock_thread_instance = Mock()
        mock_thread.return_value = mock_thread_instance
        mock_wait.return_value = True

        options = Mock()
        options.__dict__ = {
            "modules_extra_args": None,
            "skip_service_discovery": True,
            "parallel_module_scan": 10,
            "thread_per_host": 10,
            "time_sleep_between_requests": 0,
        }

        module = Module(
            module_name="vuln_scan",
            options=options,
            target="192.168.1.1",
            scan_id="test_scan",
            process_number=1,
            thread_number=1,
            total_number_threads=10,
        )

        module.module_content = {
            "payloads": [
                {
                    "library": "http",
                    "steps": [
                        [{"request": {}, "response": {}}],
                        [{"request": {}, "response": {}}],
                    ]
                }
            ]
        }
        module.libraries = ["http", "ssh", "ftp"]

        module.start()

        # 2 steps = 2 threads
        assert mock_thread.call_count == 2
        assert mock_thread_instance.start.call_count == 2

    @patch("nettacker.core.module.TemplateLoader")
    def test_start_unsupported_library(self, mock_template_loader):
        """Test starting module with unsupported library"""
        mock_template_loader.return_value.load.return_value = {
            "payloads": [{"steps": [{"response": {"conditions": {}}}]}]
        }

        options = Mock()
        options.__dict__ = {
            "modules_extra_args": None,
            "skip_service_discovery": True,
        }

        module = Module(
            module_name="custom_scan",
            options=options,
            target="192.168.1.1",
            scan_id="test_scan",
            process_number=1,
            thread_number=1,
            total_number_threads=10,
        )

        module.module_content = {
            "payloads": [
                {
                    "library": "unsupported_lib",
                    "steps": [[{"request": {}, "response": {}}]]
                }
            ]
        }
        module.libraries = ["http", "ssh", "ftp"]

        result = module.start()

        assert result is None


class TestModuleIntegration:
    """Integration tests for module workflow"""

    @patch("nettacker.core.module.TemplateLoader")
    @patch("nettacker.core.module.expand_module_steps")
    @patch("nettacker.core.module.importlib.import_module")
    @patch("nettacker.core.module.Thread")
    @patch("nettacker.core.module.wait_for_threads_to_finish")
    def test_full_module_workflow(
        self, mock_wait, mock_thread, mock_import, mock_expand, mock_template_loader
    ):
        """Test complete module workflow: load -> generate -> sort -> start"""
        mock_template_loader.return_value.load.return_value = {
            "payloads": [
                {
                    "library": "http",
                    "steps": [{"ports": [80], "request": {}, "response": {}}]
                }
            ]
        }
        mock_expand.return_value = [
            {
                "library": "http",
                "steps": [[{"ports": [80], "request": {}, "response": {}}]]
            }
        ]

        mock_engine = Mock()
        mock_import.return_value.HttpEngine.return_value = mock_engine

        mock_thread_instance = Mock()
        mock_thread.return_value = mock_thread_instance
        mock_wait.return_value = True

        options = Mock()
        options.__dict__ = {
            "modules_extra_args": None,
            "skip_service_discovery": True,
            "excluded_ports": None,
            "parallel_module_scan": 10,
            "thread_per_host": 10,
            "time_sleep_between_requests": 0,
        }

        module = Module(
            module_name="port_scan",
            options=options,
            target="192.168.1.1",
            scan_id="test_scan",
            process_number=1,
            thread_number=1,
            total_number_threads=10,
        )
        module.libraries = ["http", "ssh", "ftp"]

        # Execute full workflow
        module.load()
        assert module.module_content is not None

        module.generate_loops()
        mock_expand.assert_called_once()

        module.sort_loops()
        assert module.module_content["payloads"] is not None

        module.start()
        mock_thread_instance.start.assert_called()
