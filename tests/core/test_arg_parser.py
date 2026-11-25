import pytest

from nettacker.core.arg_parser import ArgParser


def _build_arg_parser(monkeypatch, tmp_path, argv_tail):
    report_path = str(tmp_path / "report.html")
    argv = [
        "nettacker",
        "-i",
        "example.com",
        "--module-flow",
        "webapp_assessment",
        "-o",
        report_path,
        *argv_tail,
    ]
    monkeypatch.setattr("sys.argv", argv)
    return ArgParser()


def test_abbreviated_long_option_is_recognized_as_explicit(monkeypatch, tmp_path):
    # "--po" unambiguously abbreviates "--ports" (no other option shares that prefix).
    # argparse itself resolves the abbreviation and sets options.ports correctly; the
    # bug was that flow-input resolution used a hand-rolled exact/"=" match to decide
    # whether an option was explicitly supplied, so it didn't recognize the abbreviated
    # form and silently fell back to the flow's own default instead of the CLI value.
    ap = _build_arg_parser(monkeypatch, tmp_path, ["--po", "8000,9000"])
    assert ap.arguments.flow_inputs["ports"] == [8000, 9000]


def test_glued_short_option_is_recognized_as_explicit(monkeypatch, tmp_path):
    ap = _build_arg_parser(monkeypatch, tmp_path, ["-g8000,9000"])
    assert ap.arguments.flow_inputs["ports"] == [8000, 9000]


def test_unset_option_falls_back_to_flow_default(monkeypatch, tmp_path):
    ap = _build_arg_parser(monkeypatch, tmp_path, [])
    assert ap.arguments.flow_inputs["ports"] == [21, 22, 80, 443, 8080, 8443]


def test_exclude_modules_with_module_flow_is_rejected(monkeypatch, tmp_path):
    # --exclude-modules only ever filtered options.selected_modules, but the flow
    # scheduler launches every step from the flow's own step list regardless of that
    # filtered selection - so a step using an "excluded" module would still run.
    # Reject the combination outright instead of silently ignoring the exclusion.
    with pytest.raises(SystemExit):
        _build_arg_parser(monkeypatch, tmp_path, ["--exclude-modules", "port_scan"])


def test_append_action_option_does_not_crash(monkeypatch, tmp_path):
    # -H/--add-http-header uses action="append". _explicitly_provided_dests() used to
    # swap every action's default for a plain sentinel object before re-parsing, and
    # argparse's _AppendAction calls .append() on the *current* dest value - crashing
    # with AttributeError when that value was the sentinel instead of a list.
    ap = _build_arg_parser(monkeypatch, tmp_path, ["-H", "X-Test: 1", "-H", "X-Test-2: 2"])
    assert ap.arguments.http_header == ["X-Test: 1", "X-Test-2: 2"]
