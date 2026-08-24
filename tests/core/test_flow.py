import pytest

from nettacker.core.flow import (
    FlowError,
    FlowLoader,
    evaluate_depends_on,
    referenced_step_ids,
    render_params,
)


def make_flow_content(steps, execution=None, defaults=None, inputs=None):
    return {
        "info": {"name": "test_flow"},
        "inputs": inputs or {},
        "defaults": defaults or {},
        "execution": execution or {},
        "steps": steps,
    }


class DummyOptions:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __getattr__(self, name):
        return None


def test_build_simple_linear_flow():
    content = make_flow_content(
        [
            {"id": "a", "module": "port_scan", "depends_on": []},
            {"id": "b", "module": "dir_scan", "depends_on": ["a"]},
        ]
    )
    flow = FlowLoader.build(content)
    assert flow.step_ids() == ["a", "b"]
    assert flow.max_parallel == 4
    assert flow.on_failure == "continue"


def test_execution_uses_configured_max_parallel():
    content = make_flow_content(
        [{"id": "a", "module": "port_scan", "depends_on": []}],
        execution={"max_parallel": 8},
    )
    flow = FlowLoader.build(content)
    assert flow.max_parallel == 8


def test_missing_steps_raises():
    with pytest.raises(FlowError):
        FlowLoader.build({"info": {}, "steps": []})


def test_step_missing_id_or_module_raises():
    content = make_flow_content([{"id": "a"}])
    with pytest.raises(FlowError):
        FlowLoader.build(content)


def test_duplicate_step_id_raises():
    content = make_flow_content(
        [
            {"id": "a", "module": "port_scan", "depends_on": []},
            {"id": "a", "module": "dir_scan", "depends_on": []},
        ]
    )
    with pytest.raises(FlowError):
        FlowLoader.build(content)


def test_unknown_dependency_raises():
    content = make_flow_content([{"id": "a", "module": "port_scan", "depends_on": ["ghost"]}])
    with pytest.raises(FlowError):
        FlowLoader.build(content)


def test_cycle_detection_raises():
    content = make_flow_content(
        [
            {"id": "a", "module": "port_scan", "depends_on": ["b"]},
            {"id": "b", "module": "dir_scan", "depends_on": ["a"]},
        ]
    )
    with pytest.raises(FlowError):
        FlowLoader.build(content)


def test_invalid_on_failure_raises():
    content = make_flow_content(
        [{"id": "a", "module": "port_scan", "depends_on": []}],
        defaults={"on_failure": "retry_forever"},
    )
    with pytest.raises(FlowError):
        FlowLoader.build(content)


def test_referenced_step_ids_flattens_nested_any_all():
    depends_on = {
        "any": [
            {"all": ["a", "b"]},
            "c",
        ]
    }
    assert referenced_step_ids(depends_on) == {"a", "b", "c"}


@pytest.mark.parametrize(
    "depends_on,completed,blocked,expected",
    [
        ([], set(), set(), "satisfied"),
        ("a", {"a"}, set(), "satisfied"),
        ("a", set(), {"a"}, "blocked"),
        ("a", set(), set(), "pending"),
        (["a", "b"], {"a", "b"}, set(), "satisfied"),
        (["a", "b"], {"a"}, {"b"}, "blocked"),
        (["a", "b"], {"a"}, set(), "pending"),
        ({"any": ["a", "b"]}, {"a"}, set(), "satisfied"),
        ({"any": ["a", "b"]}, set(), {"a", "b"}, "blocked"),
        ({"any": ["a", "b"]}, set(), {"a"}, "pending"),
        ({"all": [{"any": ["a", "b"]}, "c"]}, {"a", "c"}, set(), "satisfied"),
        ({"all": [{"any": ["a", "b"]}, "c"]}, set(), {"a", "b"}, "blocked"),
    ],
)
def test_evaluate_depends_on(depends_on, completed, blocked, expected):
    assert evaluate_depends_on(depends_on, completed, blocked) == expected


def test_render_params_full_match_preserves_type():
    context = {"target": "example.com", "ports": [80, 443]}
    rendered = render_params({"target": "{target}", "ports": "{ports}"}, context)
    assert rendered == {"target": "example.com", "ports": [80, 443]}


def test_render_params_partial_match_stringifies():
    context = {"target": "example.com"}
    rendered = render_params({"note": "scanning {target} now"}, context)
    assert rendered == {"note": "scanning example.com now"}


def test_render_params_recurses_into_nested_structures():
    context = {"target": "example.com"}
    rendered = render_params({"nested": {"targets": ["{target}"]}}, context)
    assert rendered == {"nested": {"targets": ["example.com"]}}


def test_resolve_inputs_prefers_cli_value_over_default():
    content = make_flow_content(
        [{"id": "a", "module": "port_scan", "depends_on": []}],
        inputs={"ports": {"type": "list", "default": [80]}},
    )
    flow = FlowLoader.build(content)
    options = DummyOptions(ports=[8080])
    resolved = FlowLoader.resolve_inputs(flow, options, explicitly_provided={"ports"})
    assert resolved == {"ports": [8080]}


def test_resolve_inputs_ignores_unset_cli_default():
    # An argparse default landing in the same dest must not be mistaken for a value
    # the user actually passed - the flow's own default should win instead.
    content = make_flow_content(
        [{"id": "a", "module": "port_scan", "depends_on": []}],
        inputs={"ports": {"type": "list", "default": [80]}},
    )
    flow = FlowLoader.build(content)
    options = DummyOptions(ports=[8080])
    resolved = FlowLoader.resolve_inputs(flow, options)
    assert resolved == {"ports": [80]}


def test_resolve_inputs_falls_back_to_default():
    content = make_flow_content(
        [{"id": "a", "module": "port_scan", "depends_on": []}],
        inputs={"ports": {"type": "list", "default": [80]}},
    )
    flow = FlowLoader.build(content)
    options = DummyOptions(ports=None)
    resolved = FlowLoader.resolve_inputs(flow, options)
    assert resolved == {"ports": [80]}


def test_resolve_inputs_missing_required_raises():
    content = make_flow_content(
        [{"id": "a", "module": "port_scan", "depends_on": []}],
        inputs={"api_key": {"type": "string", "required": True}},
    )
    flow = FlowLoader.build(content)
    options = DummyOptions(api_key=None)
    with pytest.raises(FlowError):
        FlowLoader.resolve_inputs(flow, options)


def test_load_bundled_webapp_assessment_flow():
    flow = FlowLoader.load("webapp_assessment")
    assert flow.name == "webapp_assessment"
    step_ids = set(flow.step_ids())
    assert {"port_scan", "http_detect", "tls_detect", "apache_cve_check"} <= step_ids

    apache_step = next(step for step in flow.steps if step.id == "apache_cve_check")
    assert apache_step.on_failure == "abort"


def test_load_unknown_flow_name_raises():
    with pytest.raises(FlowError):
        FlowLoader.load("this_flow_does_not_exist")


def test_steps_not_a_list_raises():
    content = make_flow_content({"id": "a", "module": "port_scan", "depends_on": []})
    with pytest.raises(FlowError):
        FlowLoader.build(content)


def test_non_mapping_step_raises():
    content = make_flow_content(["port_scan"])
    with pytest.raises(FlowError):
        FlowLoader.build(content)


def test_non_mapping_section_raises():
    content = make_flow_content(
        [{"id": "a", "module": "port_scan", "depends_on": []}],
        inputs=["not", "a", "mapping"],
    )
    with pytest.raises(FlowError):
        FlowLoader.build(content)


@pytest.mark.parametrize("depends_on", [1, {"either": ["a"]}, {"any": "a"}])
def test_invalid_depends_on_shape_raises(depends_on):
    content = make_flow_content(
        [
            {"id": "a", "module": "port_scan", "depends_on": []},
            {"id": "b", "module": "dir_scan", "depends_on": depends_on},
        ]
    )
    with pytest.raises(FlowError):
        FlowLoader.build(content)
