import json

from nettacker.config import Config
from nettacker.lib.graph.d3_tree_v1.engine import escape_for_html_js


def build_report(compare_result):
    """
    generate a report based on result of comparision b/w scans

    Args:
        compare_result: dict with result of the compare

    Returns:
        Compare report in HTML
    """
    data = (
        open(Config.path.web_static_dir / "report/compare_report.html", encoding="utf-8")
        .read()
        .replace("__data_will_locate_here__", escape_for_html_js(json.dumps(compare_result)))
    )
    return data
