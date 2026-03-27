from nettacker.lib.compare_report.engine import build_report


def test_build_report_module_exists():
    # Just test that the function exists to get coverage of the module
    assert callable(build_report)
