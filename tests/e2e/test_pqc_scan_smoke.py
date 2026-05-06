"""End-to-end CLI / library smoke tests for the pqc_scan module (M3).

These are network-dependent. They are marked ``@pytest.mark.e2e`` and skip
cleanly when ``NETTACKER_NO_NETWORK_TESTS=1`` is set, or when the named
public test endpoint is unreachable from the runner.

The intent is to give one runtime confidence-check that the M1+M2
implementation works against a real PQ-aware server, not to gate CI on
the availability of any specific third-party endpoint.
"""

import os
import socket

import pytest

from nettacker.core.lib.pqc import PqcLibrary

pytestmark = pytest.mark.e2e

NO_NETWORK = os.environ.get("NETTACKER_NO_NETWORK_TESTS") == "1"


def _tcp_reachable(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


@pytest.fixture
def pqc_library() -> PqcLibrary:
    return PqcLibrary()


@pytest.mark.skipif(NO_NETWORK, reason="NETTACKER_NO_NETWORK_TESTS=1 set")
def test_smoke_ssh_pqc_against_github_or_gitlab(pqc_library):
    """GitHub and GitLab SSH endpoints typically advertise OpenSSH PQ KEX
    algorithms. Try GitHub first, fall back to GitLab. Skip if neither
    reachable from the runner."""
    candidates = [
        ("github.com", 22),
        ("gitlab.com", 22),
        ("ssh.github.com", 22),
    ]
    target = next(((h, p) for h, p in candidates if _tcp_reachable(h, p)), None)
    if target is None:
        pytest.skip("no reachable public SSH host with PQ KEX")
    host, port = target

    result = pqc_library.ssh_pqc_scan(host, port, timeout=5)
    assert result["scan_succeeded"], (
        f"smoke probe of {host}:{port} did not succeed: {result['errors']}"
    )
    # We don't assert specific advertised algorithms because public hosts'
    # configurations change. We assert the verdict is one of the four values
    # and the response shape is correct.
    assert result["verdict"] in {"pqc_ready", "hybrid_only", "classical_only", "unknown"}
    assert result["service"] == "ssh"
    assert result["ssh_server_banner"]
    assert isinstance(result["ssh_pqc_kex_advertised"], list)
    assert isinstance(result["ssh_classical_kex_advertised"], list)


@pytest.mark.skipif(NO_NETWORK, reason="NETTACKER_NO_NETWORK_TESTS=1 set")
def test_smoke_tls_pqc_against_known_pq_endpoint(pqc_library):
    """Probe a public TLS endpoint known to support PQ.

    The endpoint list is best-effort — public PQ test endpoints come and
    go. If none are reachable, skip cleanly rather than fail.
    """
    candidates = [
        ("pq.cloudflareresearch.com", 443),
        ("tls13.1d.pw", 443),
        ("openquantumsafe.org", 443),
    ]
    target = next(((h, p) for h, p in candidates if _tcp_reachable(h, p)), None)
    if target is None:
        pytest.skip("no reachable public PQ-aware TLS host")
    host, port = target

    result = pqc_library.tls_pqc_scan(host, port, timeout=5)
    # Even if the host doesn't advertise PQ today, the call must return
    # cleanly with a populated dict — not raise, not hang past timeout.
    assert isinstance(result, dict)
    assert result["service"] == "tls"
    assert result["verdict"] in {"pqc_ready", "hybrid_only", "classical_only", "unknown"}
    assert isinstance(result["tls_pqc_groups_probed"], list)
    assert len(result["tls_pqc_groups_probed"]) > 0
    assert "duration_ms" in result


@pytest.mark.skipif(NO_NETWORK, reason="NETTACKER_NO_NETWORK_TESTS=1 set")
def test_smoke_tls_pqc_does_not_hang_on_loopback_no_listener(pqc_library):
    """Negative smoke: a closed loopback port gets recorded as tcp_refused
    and the call returns within timeout, not hangs."""
    import time as _t

    start = _t.monotonic()
    result = pqc_library.tls_pqc_scan("127.0.0.1", 1, timeout=2)
    elapsed = _t.monotonic() - start
    assert elapsed < 5, f"tls_pqc_scan against closed port took {elapsed}s"
    assert result["scan_succeeded"] is False
    assert result["verdict"] == "unknown"
