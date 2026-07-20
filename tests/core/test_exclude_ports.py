import json
from unittest.mock import MagicMock, patch

import pytest

from nettacker.core.module import Module


class DummyOptions:
    def __init__(self):
        self.modules_extra_args = {"foo": "bar"}
        self.skip_service_discovery = False
        self.time_sleep_between_requests = 0
        self.thread_per_host = 2


@pytest.fixture
def options():
    return DummyOptions()


@pytest.fixture
def module_args():
    return {
        "target": "127.0.0.1",
        "scan_id": "scan123",
        "process_number": 1,
        "thread_number": 1,
        "total_number_threads": 1,
    }


@patch("nettacker.core.module.TemplateLoader")
def test_init_and_service_discovery_signature(mock_loader, options, module_args):
    mock_instance = MagicMock()
    mock_instance.load.return_value = {
        "payloads": [{"steps": [{"response": {"conditions": {"service": {"http": {}}}}}]}]
    }
    mock_loader.return_value = mock_instance

    module = Module("port_scan", options, **module_args)
    assert "http" in module.service_discovery_signatures


@patch("os.listdir", return_value=["http.py"])
@patch("nettacker.core.module.find_events")
@patch("nettacker.core.module.TemplateLoader")
def test_load_with_service_discovery(
    mock_loader, mock_find_events, mock_listdir, options, module_args
):
    mock_loader_inst = MagicMock()
    mock_loader_inst.load.return_value = {
        "payloads": [
            {
                "library": "http",
                "steps": [{"response": {"conditions": {"service": {"http": {}}}}}],
            }
        ]
    }
    mock_loader.return_value = mock_loader_inst

    mock_find_events.return_value = [
        json.dumps({"port": 80, "response": {"conditions_results": {"http": {}}}})
    ]

    module = Module("test_module", options, **module_args)
    module.load()

    assert module.discovered_services == {"http": [80]}
    assert len(module.module_content["payloads"]) == 1


@patch("nettacker.core.module.find_events")
@patch("nettacker.core.module.TemplateLoader")
def test_sort_loops(mock_loader, mock_find_events, options, module_args):
    mock_loader_inst = MagicMock()
    mock_loader_inst.load.return_value = {
        "payloads": [
            {
                "library": "http",
                "steps": [
                    {"response": {"conditions": {"service": {}}}},
                    {
                        "response": {
                            "conditions": {},
                            "dependent_on_temp_event": True,
                            "save_to_temp_events_only": True,
                        }
                    },
                    {"response": {"conditions": {}, "dependent_on_temp_event": True}},
                ],
            }
        ]
    }
    mock_loader.return_value = mock_loader_inst

    mock_find_events.return_value = [
        json.dumps({"port": 80, "response": {"conditions_results": {"http": True}}})
    ]

    module = Module("test_module", options, **module_args)
    module.libraries = ["http"]
    module.load()  # Should not raise


@patch("nettacker.core.module.find_events")
@patch("nettacker.core.module.TemplateLoader")
def test_start_unsupported_library(mock_loader, mock_find_events, options, module_args):
    mock_loader_inst = MagicMock()
    mock_loader_inst.load.return_value = {
        "payloads": [
            {
                "library": "unsupported_lib",
                "steps": [{"step_id": 1, "response": {"conditions": {"service": {}}}}],
            }
        ]
    }
    mock_loader.return_value = mock_loader_inst

    mock_find_events.return_value = [
        json.dumps({"port": 1234, "response": {"conditions_results": {"unsupported_lib": True}}})
    ]

    module = Module("test_module", options, **module_args)
    module.libraries = ["http"]
    module.service_discovery_signatures.append("unsupported_lib")

    module.load()
    result = module.start()

    assert result is None


def template_loader_side_effect(name, inputs):
    # NOT A TEST CASE
    mock_instance = MagicMock()

    # as in inside Module.__init__
    if name == "port_scan":
        mock_instance.load.return_value = {
            "payloads": [{"steps": [{"response": {"conditions": {"service": {"http": {}}}}}]}]
        }
    # as in module.load()
    elif name == "test_module":
        mock_instance.load.return_value = {
            "payloads": [
                {
                    "library": "http",
                    "steps": [
                        [{"response": {"conditions": {"service": {}}}}],
                        [
                            {
                                "response": {
                                    "conditions": {},
                                    "dependent_on_temp_event": True,
                                    "save_to_temp_events_only": True,
                                }
                            }
                        ],
                        [{"response": {"conditions": {}, "dependent_on_temp_event": True}}],
                    ],
                }
            ]
        }
    else:
        raise ValueError(f"Unexpected module name: {name}")

    return mock_instance


@patch("nettacker.core.module.TemplateLoader.parse", side_effect=lambda step, _: step)
@patch("nettacker.core.module.find_events")
@patch("nettacker.core.module.TemplateLoader")
def test_sort_loops_behavior(mock_loader_cls, mock_find_events, mock_parse, options, module_args):
    # This one is painful
    mock_loader_cls.side_effect = template_loader_side_effect

    mock_find_events.return_value = [
        json.dumps({"port": 80, "response": {"conditions_results": {"http": True}}})
    ]

    module = Module("test_module", options, **module_args)
    module.libraries = ["http"]
    module.load()
    module.sort_loops()

    steps = module.module_content["payloads"][0]["steps"]

    assert steps[0][0]["response"]["conditions"] == {"service": {}}
    assert steps[1][0]["response"]["dependent_on_temp_event"] is True
    assert steps[1][0]["response"]["save_to_temp_events_only"] is True
    assert steps[2][0]["response"]["dependent_on_temp_event"] is True
    assert "save_to_temp_events_only" not in steps[2][0]["response"]


def start_test_loader_side_effect(name, inputs):
    # HELPER for start test
    mock_inst = MagicMock()

    if name == "port_scan":
        mock_inst.load.return_value = {
            "payloads": [{"steps": [{"response": {"conditions": {"service": {"http": {}}}}}]}]
        }
    elif name == "test_module":
        mock_inst.load.return_value = {
            "payloads": [
                {
                    "library": "http",
                    "steps": [[{"response": {}, "id": 1}], [{"response": {}, "id": 2}]],
                }
            ]
        }
    else:
        raise ValueError(f"Unexpected module name: {name}")

    return mock_inst


@patch("nettacker.core.module.TemplateLoader.parse", side_effect=lambda x, _: x)
@patch("nettacker.core.module.log")
@patch("nettacker.core.module.TemplateLoader")
@patch("nettacker.core.module.find_events")
def test_start_library_not_supported(
    mock_find_events,
    mock_loader_cls,
    mock_log,
    mock_parse,
    module_args,
):
    def loader_side_effect_specific(name, inputs):
        mock_inst = MagicMock()
        if name == "port_scan":
            mock_inst.load.return_value = {
                "payloads": [{"steps": [{"response": {"conditions": {"service": {"http": {}}}}}]}]
            }
        elif name == "test_module":
            mock_inst.load.return_value = {
                "payloads": [
                    {
                        "library": "unsupported_lib",
                        "steps": [
                            [{"id": 1}],
                        ],
                    }
                ]
            }
        return mock_inst

    mock_loader_cls.side_effect = loader_side_effect_specific

    mock_event = MagicMock()
    mock_event.json_event = json.dumps(
        {"port": 80, "response": {"conditions_results": {"http": True}}}
    )
    mock_find_events.return_value = [mock_event]

    # Had to add this small workaround
    class DummyOptionsSpecific:
        def __init__(self):
            self.modules_extra_args = {}
            self.skip_service_discovery = True
            self.time_sleep_between_requests = 0
            self.thread_per_host = 2

    options = DummyOptionsSpecific()

    module = Module("test_module", options, **module_args)
    module.libraries = ["http"]
    module.load()

    result = module.start()

    assert result is None
    mock_log.warn.assert_called_once()
    assert "unsupported_lib" in mock_log.warn.call_args[0][0]


@patch("nettacker.core.module.TemplateLoader.parse", side_effect=lambda step, _: step)
@patch("nettacker.core.module.find_events")
@patch("nettacker.core.module.TemplateLoader")
def test_load_appends_port_to_existing_protocol(
    mock_loader_cls,
    mock_find_events,
    mock_parse,
    options,
    module_args,
):
    def loader_side_effect_specific(name, inputs):
        mock_inst = MagicMock()
        mock_inst.load.return_value = {
            "payloads": [
                {
                    "library": "http",
                    "steps": [
                        {"response": {"conditions": {"service": {}}}}  # .load() requires no []
                    ],
                }
            ]
        }
        return mock_inst

    mock_loader_cls.side_effect = loader_side_effect_specific
    mock_find_events.return_value = [
        json.dumps({"port": 80, "response": {"conditions_results": {"http": {}}}}),
        json.dumps({"port": 443, "response": {"conditions_results": {"http": {}}}}),
    ]

    module = Module("test_module", options, **module_args)
    module.libraries = ["http"]
    module.service_discovery_signatures = ["http"]
    module.load()
    assert module.discovered_services == {"http": [80, 443]}


@patch("nettacker.core.module.expand_module_steps")
@patch("nettacker.core.module.TemplateLoader")
def test_generate_loops_with_excluded_ports_and_ports_in_content(
    mock_loader, mock_expand_steps, options, module_args
):
    mock_instance = MagicMock()
    return_value = {
        "payloads": [
            {
                "steps": [
                    {
                        "ports": [80, 443, 8080],
                        "response": {"conditions": {"service": {}}},
                    }
                ]
            }
        ]
    }
    mock_instance.load.return_value = return_value
    mock_loader.return_value = mock_instance

    mock_expand_steps.side_effect = lambda x: x

    module = Module("test_module", options, **module_args)
    module.module_inputs = {"excluded_ports": [443, 8080]}
    module.module_content = return_value
    module.generate_loops()

    expected_ports = [80]  # 443 and 8080 should be excluded
    actual_ports = module.module_content["payloads"][0]["steps"][0]["ports"]
    assert actual_ports == expected_ports


@patch("nettacker.core.module.expand_module_steps")
@patch("nettacker.core.module.TemplateLoader")
def test_generate_loops_with_excluded_ports_no_ports_in_content(
    mock_loader, mock_expand_steps, options, module_args
):
    mock_instance = MagicMock()
    return_value = {
        "payloads": [
            {
                "steps": [
                    {
                        "ports": [80, 443, 8080],
                        "response": {"conditions": {"service": {}}},
                    }
                ]
            }
        ]
    }

    mock_instance.load.return_value = return_value
    mock_loader.return_value = mock_instance

    mock_expand_steps.side_effect = lambda x: x

    module = Module("test_module", options, **module_args)
    module.module_inputs = {"excluded_ports": None}
    module.module_content = return_value
    module.generate_loops()

    expected_ports = [80, 443, 8080]
    actual_ports = module.module_content["payloads"][0]["steps"][0]["ports"]
    assert actual_ports == expected_ports
