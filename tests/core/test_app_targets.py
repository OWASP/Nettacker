from types import SimpleNamespace

from nettacker.core.app import Nettacker


def test_explicit_url_port_and_scheme_skip_service_discovery():
    app = Nettacker.__new__(Nettacker)
    app.arguments = SimpleNamespace(
        targets=["http://jshop:3000/shop"],
        scan_ip_range=False,
        scan_subdomains=False,
        ping_before_scan=False,
        selected_modules=["http_status_scan"],
        skip_service_discovery=False,
        ports=None,
        schema=None,
        url_base_path=None,
    )

    targets = app.expand_targets("scan-id")

    assert targets == ["jshop"]
    assert app.arguments.ports == [3000]
    assert app.arguments.schema == ["http"]
    assert app.arguments.skip_service_discovery is True
    assert app.arguments.url_base_path == "shop/"
