import time
from types import SimpleNamespace

from nettacker.core import app as app_module
from nettacker.core.app import Nettacker
from nettacker.core.flow import Flow, FlowStep


class _FakeScanner:
    """Minimal stand-in exposing just what Nettacker.scan_flow_group needs from self."""

    def __init__(self, scan_target, parallel_module_scan=2):
        self.arguments = SimpleNamespace(parallel_module_scan=parallel_module_scan, flow_inputs={})
        self._scan_target = scan_target

    def scan_target(self, *args, **kwargs):
        return self._scan_target(*args, **kwargs)

    scan_flow_group = Nettacker.scan_flow_group


def test_concurrent_steps_sharing_a_module_do_not_inherit_success(monkeypatch):
    """
    Two independent steps (a_step, b_step) both invoke module "shared_mod" for the
    same target, with no dependency between them, so they'd be eligible to launch in
    the same scheduler pass. Events are only identifiable by (target, module,
    scan_id), so if both steps ran concurrently they'd share an ambiguous event-count
    baseline: a_step's real success could make b_step's failure look like a success
    too. The scheduler must serialize same-module steps per target instead.
    """
    flow = Flow(
        name="test_flow",
        info={},
        inputs={},
        on_failure="continue",
        max_parallel=4,
        steps=[
            FlowStep(id="a_step", module="shared_mod", depends_on=[]),
            FlowStep(id="b_step", module="shared_mod", depends_on=[]),
        ],
    )

    events = []
    call_count = {"n": 0}
    call_windows = []  # (start, end) wall-clock time per scan_target invocation

    def fake_find_events(target, module_name, scan_id):
        return events

    def fake_scan_target(
        target, module, scan_id, process_number, counter, total, extra_options=None
    ):
        start = time.monotonic()
        call_count["n"] += 1
        if call_count["n"] == 1:
            # First step to run "succeeds" (produces an event), but takes long enough
            # that a concurrently-launched second step would still be mid-flight.
            time.sleep(0.15)
            events.append(1)
        # Every subsequent step invocation "fails": no new event produced.
        call_windows.append((start, time.monotonic()))

    monkeypatch.setattr(app_module, "find_events", fake_find_events)

    scanner = _FakeScanner(fake_scan_target)
    result = scanner.scan_flow_group(flow, ["1.2.3.4"], "scan-id", 1, [])

    assert result is True
    assert call_count["n"] == 2
    # The two same-module steps must be serialized, not launched concurrently -
    # otherwise they'd share an ambiguous event-count baseline and the second step
    # could inherit the first one's success even though it produced no event itself.
    (start_a, end_a), (start_b, end_b) = call_windows
    assert start_b >= end_a
    # Exactly one of the two steps may be credited with success; the other must not
    # inherit it just because it shares a module with the one that actually ran.
    assert len(events) == 1
