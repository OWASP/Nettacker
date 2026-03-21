import json
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

from nettacker.core.graph import (
    build_compare_report,
    build_graph,
    build_text_table,
    create_compare_report,
    create_compare_text_table,
    create_report,
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
@patch("nettacker.core.graph.Path.open", new_callable=mock_open)
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
@patch("nettacker.core.graph.Path.open", new_callable=mock_open)
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
@patch("nettacker.core.graph.Path.open", new_callable=mock_open)
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
@patch("nettacker.core.graph.Path.open", new_callable=mock_open)
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
@patch("nettacker.core.graph.Path.open", new_callable=mock_open)
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

# SARIF & DefectDojo Extension Tests

@patch("nettacker.core.graph.all_module_severity_and_desc", {"port_scan": {"severity": 7, "desc": "Port scan module"}})
def test_sarif_report_structure():
    from nettacker.core.graph import create_sarif_report
    log_data = [{
        "module_name": "port_scan",
        "date": "2026-03-21 10:00:00",
        "port": 80,
        "event": "open port",
        "json_event": {"status": "open"},
        "target": "127.0.0.1",
        "scan_id": "test_id_123"
    }]
    
    result = create_sarif_report(log_data)
    sarif = json.loads(result)
    
    assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    
    # Check driver configuration
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "Nettacker"
    assert "version" in driver
    
    # Check rule population
    assert len(driver["rules"]) == 1
    rule = driver["rules"][0]
    assert rule["id"] == "port_scan"
    assert rule["defaultConfiguration"]["level"] == "error" # severity 7 -> error
    
    # Check results
    assert len(sarif["runs"][0]["results"]) == 1
    res = sarif["runs"][0]["results"][0]
    assert res["ruleId"] == "port_scan"
    assert res["level"] == "error"
    assert "locations" in res
    assert "webRequest" in res
    assert "partialFingerprints" in res

@patch("nettacker.core.graph.all_module_severity_and_desc", {
    "high_mod": {"severity": 8},
    "med_mod": {"severity": 5},
    "low_mod": {"severity": 2},
    "info_mod": {"severity": 0}
})
def test_sarif_report_severity_mapping():
    from nettacker.core.graph import create_sarif_report
    logs = [
        {"module_name": "high_mod", "date": "1", "port": "", "event": "", "json_event": "", "target": "", "scan_id": ""},
        {"module_name": "med_mod", "date": "1", "port": "", "event": "", "json_event": "", "target": "", "scan_id": ""},
        {"module_name": "low_mod", "date": "1", "port": "", "event": "", "json_event": "", "target": "", "scan_id": ""},
        {"module_name": "info_mod", "date": "1", "port": "", "event": "", "json_event": "", "target": "", "scan_id": ""}
    ]
    
    sarif = json.loads(create_sarif_report(logs))
    results = sarif["runs"][0]["results"]
    
    levels = [r["level"] for r in results]
    assert levels == ["error", "warning", "note", "none"]

@patch("nettacker.core.graph.all_module_severity_and_desc", {"port_scan": {"severity": 7}})
def test_dd_specific_json_structure():
    from nettacker.core.graph import create_dd_specific_json
    log_data = [{
        "module_name": "port_scan",
        "date": "2026-03-21 10:00:00.000000",
        "port": 80,
        "event": "open port",
        "json_event": {"status": "open"},
        "target": "127.0.0.1",
        "scan_id": "test_id_123"
    }]
    
    result = create_dd_specific_json(log_data)
    dd_json = json.loads(result)
    
    assert "findings" in dd_json
    assert len(dd_json["findings"]) == 1
    
    finding = dd_json["findings"][0]
    # Date should be reformatted to MM/DD/YYYY
    assert finding["date"] == "03/21/2026"
    assert finding["title"] == "port_scan"
    assert finding["severity"] == "High"  # severity 7 -> High
    assert finding["test_type"] == "Nettacker Scan"
    
def test_dd_specific_json_no_strip_bug():
    from nettacker.core.graph import create_dd_specific_json
    """Verify that no AttributeError is thrown when event/json_event are dicts"""
    log_data = [{
        "module_name": "test_mod",
        "date": "2026-03-21 10:00:00",
        # These dicts previously caused an AttributeError: 'dict' object has no attribute 'strip'
        "port": {"p": 80},
        "event": {"msg": "found"},
        "json_event": {"status": 200}, 
        "target": "1.2.3.4",
        "scan_id": "test"
    }]
    
    try:
        result = create_dd_specific_json(log_data)
        dd_json = json.loads(result)
        
        # Verify it converted them to json strings safely
        assert "{" in dd_json["findings"][0]["impact"]
        assert "{" in dd_json["findings"][0]["severity_justification"]
        assert "{" in dd_json["findings"][0]["param"]
    except AttributeError:
        pytest.fail("create_dd_specific_json raised AttributeError due to `.strip()` bug on dicts")

@patch("nettacker.core.graph.get_logs_by_scan_id", return_value=[{"date": "2026-03-21 10:00:00", "target": "1", "module_name": "m", "port": "80", "event": "e", "json_event": "{}", "scan_id": "1"}])
@patch("nettacker.core.graph.Path")
@patch("nettacker.core.graph.submit_report_to_db")
def test_sarif_file_created(mock_submit, mock_path, mock_get_logs):
    options = MagicMock()
    options.report_path_filename = "report.sarif"
    
    # Enable reading from the mock path
    mock_file = MagicMock()
    mock_path.return_value.open.return_value.__enter__.return_value = mock_file
    
    result = create_report(options, "scan-id")
    assert result is True
    # Verify open was called correctly for a .sarif file
    mock_path.assert_called_with("report.sarif")
    mock_path.return_value.open.assert_called_with("w", encoding="utf-8")
    mock_file.write.assert_called()

@patch("nettacker.core.graph.get_logs_by_scan_id", return_value=[{"date": "2026-03-21 10:00:00", "target": "1", "module_name": "m", "port": "80", "event": "e", "json_event": "{}", "scan_id": "1"}])
@patch("nettacker.core.graph.Path")
@patch("nettacker.core.graph.submit_report_to_db")
def test_dd_file_created_and_auto_push(mock_submit, mock_path, mock_get_logs):
    options = MagicMock()
    options.report_path_filename = "report.dd.json"
    options.defectdojo_auto_push = True
    options.defectdojo_url = "http://test"
    options.defectdojo_api_key = "key"
    options.defectdojo_product_name = "prod"
    options.defectdojo_engagement_name = "eng"
    
    # Enable reading from the mock path
    mock_file = MagicMock()
    mock_path.return_value.open.return_value.__enter__.return_value = mock_file
    
    from nettacker.lib.export.defectdojo import DefectDojoClient
    with patch("nettacker.lib.export.defectdojo.DefectDojoClient.push_findings") as mock_push:
        result = create_report(options, "scan-id")
        
        assert result is True
        mock_path.assert_called_with("report.dd.json")
        mock_path.return_value.open.assert_called_with("w", encoding="utf-8")
        mock_file.write.assert_called()
        mock_push.assert_called_once()
