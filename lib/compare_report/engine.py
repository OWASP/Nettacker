import json

from nettacker.config import Config


def build_report(compare_result):
    """
    generate a report based on result of comparision b/w scans

    Args:
        compare_result: dict with result of the compare

    Returns:
        Compare report in HTML
    """
    data = (
        open(Config.path.web_static_dir / "report/compare_report.html")
        .read()
        .replace("__data_will_locate_here__", json.dumps(compare_result))
    )
    return data
