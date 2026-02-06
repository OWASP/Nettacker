from types import SimpleNamespace

from nettacker.core.module import Module


def test_module_load_does_not_require_discovered_service_for_unknown_library(monkeypatch):
    # shodan_scan uses a non-port based library and should not crash during service discovery.
    # Avoid hitting the real DB layer in unit tests.
    import nettacker.core.module as module_mod

    monkeypatch.setattr(module_mod, "find_events", lambda *_args, **_kwargs: [])

    options = SimpleNamespace(
        modules_extra_args=None,
        skip_service_discovery=False,
        excluded_ports=None,
        time_sleep_between_requests=0.0,
        thread_per_host=1,
        retries=1,
        user_agent="test-agent",
        http_header=None,
        socks_proxy=None,
        # common defaults expected by Module.start() but not used here
        user_agents=[],
    )
    m = Module(
        module_name="shodan_scan",
        options=options,
        target="example.com",
        scan_id="test-scan-id",
        process_number=0,
        thread_number=0,
        total_number_threads=1,
    )
    m.load()
    assert m.module_content["payloads"][0]["library"] == "shodan"

