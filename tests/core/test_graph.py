import json
import sys
import types
from unittest.mock import patch, mock_open, MagicMock

import pytest

from nettacker.core.graph import (
    build_graph,
    build_compare_report,
    build_text_table,
    create_compare_text_table,
    create_report,
    create_compare_report,
)


class DummyOptions:
    def __init__(self, scan_compare_id, compare_report_path_filename):
        self.scan_compare_id = scan_compare_id
        self.compare_report_path_filename = compare_report_path_filename


@patch("nettacker.core.graph.importlib.import_module")
def test_build_graph_success(mock_import_module):
    mock_start = MagicMock(return_value="<graph_html>")
    mock_import_module.return_value.start = mock_start

    result = build_graph("foo_graph", ["event1"])
    assert result == "<graph_html>"
    mock_import_module.assert_called_once()


@patch("nettacker.core.graph.die_failure")
@patch("nettacker.core.graph.importlib.import_module", side_effect=ModuleNotFoundError)
@pytest.mark.xfail(reason="It will hit an UnboundLocalError")
def test_build_graph_module_not_found(mock_import_module, mock_die_failure):
    build_graph("missing_graph", [])
    mock_die_failure.assert_called_once()


@patch("nettacker.core.graph.importlib.import_module")
def test_build_compare_report_success(mock_import_module):
    mock_build_report = MagicMock(return_value="<compare_html>")
    mock_import_module.return_value.build_report = mock_build_report
    result = build_compare_report({"some": "results"})
    assert result == "<compare_html>"


@patch("nettacker.core.graph.die_failure")
@patch("nettacker.core.graph.importlib.import_module", side_effect=ModuleNotFoundError)
@pytest.mark.xfail(reason="It will hit an UnboundLocalError")
def test_build_compare_report_module_not_found(mock_import_module, mock_die_failure):
    build_compare_report({"some": "results"})
    mock_die_failure.assert_called_once()


@patch("nettacker.core.graph.merge_logs_to_list", return_value=["event1", "event2"])
@patch("nettacker.core.graph.version_info", return_value=("1.0", "beta"))
@patch("nettacker.core.graph.now", return_value="now")
def test_build_text_table(mock_now, mock_version_info, mock_merge_logs):
    events = [
        {
            "date": "today",
            "target": "127.0.0.1",
            "module_name": "port_scan",
            "port": 80,
            "json_event": json.dumps({"some": "event"}),
        }
    ]
    result = build_text_table(events)
    assert "127.0.0.1" in result
    assert "now" in result


def test_create_compare_text_table():
    results = {"A": "value1", "B": "value2"}
    table_output = create_compare_text_table(results)
    assert (
        "+---+---+\n| A | B |\n+===+===+\n| v | v |\n| a | a |\n| l | l |\n| u | u |\n| e | e |\n| 1 | 2 |\n+---+---+\n\n"
        in table_output
    )


@patch("nettacker.core.graph.get_logs_by_scan_id", return_value=[])
@patch("nettacker.core.graph.log.info")
def test_no_events(mock_log_info, mock_get_logs):
    options = MagicMock()
    options.report_path_filename = "report.html"
    result = create_report(options, "scan-id")
    assert result is True
    mock_log_info.assert_called()


@patch(
    "nettacker.core.graph.get_logs_by_scan_id",
    return_value=[
        {"date": "now", "target": "x", "module_name": "mod", "port": 80, "json_event": "{}"}
    ],
)
@patch("nettacker.core.graph.version_info", return_value=("1.0", "beta"))
@patch("nettacker.core.graph.now", return_value="now")
@patch("nettacker.core.graph.submit_report_to_db")
@patch("builtins.open", new_callable=mock_open)
@patch("nettacker.core.graph.merge_logs_to_list", return_value=["log1", "log2"])
def test_create_report_html(
    mock_merge_logs, mock_open_file, mock_submit, mock_now, mock_version, mock_get_logs
):
    fake_log_data = types.SimpleNamespace(
        css_1="/*css*/",
        json_parse_js="<script>/*js*/</script>",
        table_end="</table>",
        table_items="<tr>{}{}</tr>",
        table_title="<table>{}{}</table>{}{}{}{}{}{}",
    )

    with patch.dict(sys.modules, {"nettacker.lib.html_log.log_data": fake_log_data}):
        options = MagicMock()
        options.report_path_filename = "report.html"
        options.graph_name = None

        result = create_report(options, "scan-id")
        assert result is True
        mock_submit.assert_called_once()


@patch(
    "nettacker.core.graph.get_logs_by_scan_id",
    return_value=[
        {"date": "now", "target": "x", "module_name": "mod", "port": 80, "json_event": "{}"}
    ],
)
@patch("builtins.open", new_callable=mock_open)
@patch("nettacker.core.graph.submit_report_to_db")
def test_json_report(mock_submit, mock_open_file, mock_get_logs):
    options = MagicMock()
    options.report_path_filename = "report.json"
    result = create_report(options, "scan-id")
    assert result is True
    mock_open_file.assert_called_once()
    mock_submit.assert_called_once()


@patch(
    "nettacker.core.graph.get_logs_by_scan_id",
    return_value=[
        {"date": "now", "target": "x", "module_name": "mod", "port": 80, "json_event": "{}"}
    ],
)
@patch("csv.DictWriter")
@patch("builtins.open", new_callable=mock_open)
@patch("nettacker.core.graph.submit_report_to_db")
def test_csv_report(mock_submit, mock_open_file, mock_csv_writer, mock_get_logs):
    options = MagicMock()
    options.report_path_filename = "report.csv"
    mock_writer_instance = MagicMock()
    mock_csv_writer.return_value = mock_writer_instance
    result = create_report(options, "scan-id")
    assert result is True
    mock_writer_instance.writeheader.assert_called_once()
    mock_writer_instance.writerow.assert_called_once()


@patch(
    "nettacker.core.graph.get_logs_by_scan_id",
    return_value=[
        {"date": "now", "target": "x", "module_name": "mod", "port": 80, "json_event": "{}"}
    ],
)
@patch("nettacker.core.graph.build_text_table", return_value="text table")
@patch("builtins.open", new_callable=mock_open)
@patch("nettacker.core.graph.submit_report_to_db")
def test_text_report(mock_submit, mock_open_file, mock_build_text, mock_get_logs):
    options = MagicMock()
    options.report_path_filename = "report.txt"
    result = create_report(options, "scan-id")
    assert result is True
    mock_build_text.assert_called()
    mock_submit.assert_called_once()


@patch("nettacker.core.graph.get_logs_by_scan_id")
@patch("nettacker.core.graph.get_options_by_scan_id")
@patch("nettacker.core.graph.build_compare_report", return_value="<html-report>")
@patch("nettacker.core.graph.open", new_callable=mock_open)
@patch("nettacker.core.graph.os.path.normpath", side_effect=lambda x: x)
@patch("nettacker.core.graph.os.path.join", side_effect=lambda *args: "/".join(args))
@patch("nettacker.core.graph.create_compare_text_table", return_value="text-report")
def test_html_json_csv_text(
    mock_text_table,
    mock_join,
    mock_norm,
    mock_open_file,
    mock_build_html,
    mock_get_opts,
    mock_get_logs,
):
    options_html = DummyOptions("scan-comp", "report.html")
    options_json = DummyOptions("scan-comp", "report.json")
    options_csv = DummyOptions("scan-comp", "report.csv")
    options_txt = DummyOptions("scan-comp", "report.txt")

    dummy_log = {
        "target": "1.1.1.1",
        "module_name": "mod",
        "port": 80,
        "date": "now",
        "options": json.dumps({"targets": ["1.1.1.1"]}),
    }

    mock_get_logs.side_effect = lambda x: [dummy_log] if x == "scan-1" or x == "scan-comp" else []
    mock_get_opts.side_effect = lambda x: [dummy_log]

    for opt in [options_html, options_json, options_csv, options_txt]:
        result = create_compare_report(opt, "scan-1")
        assert result is True
        assert mock_open_file.called is True


@patch("nettacker.core.graph.get_logs_by_scan_id", return_value=[])
def test_no_current_logs(mock_logs):
    result = create_compare_report(DummyOptions("scan-comp", "report.html"), "scan-1")
    assert result is None


@patch("nettacker.core.graph.get_logs_by_scan_id")
def test_no_comparison_logs(mock_logs):
    def logs_side_effect(scan_id):
        return (
            [
                {
                    "date": "now",
                    "target": "x",
                    "module_name": "mod",
                    "port": 80,
                    "options": json.dumps({"targets": ["x"]}),
                }
            ]
            if scan_id == "scan-1"
            else []
        )

    mock_logs.side_effect = logs_side_effect
    result = create_compare_report(DummyOptions("scan-comp", "report.html"), "scan-1")
    assert result is None


@patch("nettacker.core.graph.get_logs_by_scan_id")
@patch("nettacker.core.graph.get_options_by_scan_id")
@patch("nettacker.core.graph.os.path.normpath", side_effect=lambda x: "/etc/passwd")
@patch("nettacker.core.graph.os.path.join", side_effect=lambda *args: "/etc/passwd")
def test_permission_error(mock_join, mock_norm, mock_opts, mock_logs):
    dummy_log = {
        "target": "1.1.1.1",
        "module_name": "mod",
        "port": 80,
        "date": "now",
        "options": json.dumps({"targets": ["1.1.1.1"]}),
    }
    mock_logs.return_value = [dummy_log]
    mock_opts.return_value = [dummy_log]

    with pytest.raises(PermissionError):
        create_compare_report(DummyOptions("scan-comp", "report.html"), "scan-1")


@patch("nettacker.core.graph.get_logs_by_scan_id")
@patch("nettacker.core.graph.get_options_by_scan_id")
@patch("nettacker.core.graph.create_compare_text_table", return_value="some-text")
@patch("nettacker.core.graph.open", new_callable=mock_open)
def test_dict_options(mock_open_file, mock_text, mock_opts, mock_logs):
    dummy_log = {
        "target": "1.1.1.1",
        "module_name": "mod",
        "port": 80,
        "date": "now",
        "options": json.dumps({"targets": ["1.1.1.1"]}),
    }
    mock_logs.return_value = [dummy_log]
    mock_opts.return_value = [dummy_log]

    options_dict = {
        "scan_compare_id": "scan-comp",
        "compare_report_path_filename": "report.json",
    }

    result = create_compare_report(options_dict, "scan-1")
    assert result is True
    mock_open_file.assert_called()


@patch("nettacker.core.graph.build_graph", return_value="<graph_html>")
@patch(
    "nettacker.core.graph.get_logs_by_scan_id",
    return_value=[
        {"date": "now", "target": "x", "module_name": "mod", "port": 80, "json_event": "{}"}
    ],
)
@patch("nettacker.core.graph.now", return_value="now")
@patch("nettacker.core.graph.version_info", return_value=("1.0", "beta"))
@patch("builtins.open", new_callable=mock_open)
@patch("nettacker.core.graph.merge_logs_to_list", return_value=["log1", "log2"])
@patch("nettacker.core.graph.submit_report_to_db")
def test_create_report_with_graph_name(
    mock_submit,
    mock_merge_logs,
    mock_open_file,
    mock_version,
    mock_now,
    mock_get_logs,
    mock_build_graph,
):
    fake_log_data = types.SimpleNamespace(
        css_1="/*css*/",
        json_parse_js="<script>/*js*/</script>",
        table_end="</table>",
        table_items="<tr>{}{}</tr>",
        table_title="<table>{}{}</table>{}{}{}{}{}{}",
    )

    with patch.dict(sys.modules, {"nettacker.lib.html_log.log_data": fake_log_data}):
        options = MagicMock()
        options.report_path_filename = "report.html"
        options.graph_name = "bar_graph"

        result = create_report(options, "scan-id")
        assert result is True
        mock_build_graph.assert_called_once_with(
            "bar_graph",
            [
                {
                    "date": "now",
                    "target": "x",
                    "module_name": "mod",
                    "port": 80,
                    "json_event": "{}",
                }
            ],
        )
