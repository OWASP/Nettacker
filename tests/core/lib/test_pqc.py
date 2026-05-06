"""Unit + integration tests for ``nettacker.core.lib.pqc`` (M1 — SSH path only)."""

import socket
import struct
import threading
import time
from typing import Iterator

import pytest

from nettacker.core.lib.pqc import (
    SSH_PQC_KEX_ALGORITHMS,
    TLS_PQC_NAMED_GROUPS,
    PqcEngine,
    PqcLibrary,
    Verdict,
    _classify_ssh_kex,
    _parse_ssh_kexinit,
    _provisional_verdict_ssh,
    _safe_ssh_name,
)

# ---------- Pure-function tests ----------------------------------------------


class TestAlgorithmTables:
    def test_ssh_table_within_v1_cap(self):
        # F-SEC bound — table must remain ≤4 in v1.
        assert len(SSH_PQC_KEX_ALGORITHMS) <= 4

    def test_ssh_table_entries_well_formed(self):
        required_keys = {"kind", "status", "since_openssh_version", "source"}
        for name, entry in SSH_PQC_KEX_ALGORITHMS.items():
            assert required_keys.issubset(entry.keys()), (
                f"{name} missing required keys: {required_keys - set(entry.keys())}"
            )
            assert entry["kind"] in {"pure_pq", "hybrid"}
            assert entry["status"] in {"standardized", "draft", "experimental"}

    def test_ssh_table_includes_openssh_defaults(self):
        # Per the runbook + research synthesis, both OpenSSH-shipped PQ KEX
        # algorithms must be present in v1.
        assert "sntrup761x25519-sha512@openssh.com" in SSH_PQC_KEX_ALGORITHMS
        assert "mlkem768x25519-sha256" in SSH_PQC_KEX_ALGORITHMS

    def test_tls_table_placeholder_for_m1(self):
        # M2 finalizes this. M1 only requires the constant exists for import.
        assert isinstance(TLS_PQC_NAMED_GROUPS, dict)


class TestSafeSshName:
    @pytest.mark.parametrize(
        "raw",
        [
            b"mlkem768x25519-sha256",
            b"sntrup761x25519-sha512@openssh.com",
            b"curve25519-sha256",
            b"ecdh-sha2-nistp256",
            b"ssh-ed25519",
        ],
    )
    def test_valid_names_accepted(self, raw):
        assert _safe_ssh_name(raw) == raw.decode("ascii")

    @pytest.mark.parametrize(
        "raw",
        [
            b"\nINJECTED",
            b"alg\x00null",
            b"alg with space",
            b"a,b",  # comma is the name-list separator, never inside a name
            b"\xff\xfe",
            b"a;b",
            b"alg\rcr",
            b"",  # empty name not allowed
        ],
    )
    def test_malformed_names_rejected(self, raw):
        assert _safe_ssh_name(raw) is None


class TestParseSshKexinit:
    @staticmethod
    def _build_kexinit(namelists: list[bytes]) -> bytes:
        """Encode a fake SSH_MSG_KEXINIT payload for testing."""
        assert len(namelists) == 10
        body = bytes([20]) + b"\x00" * 16  # msg type + cookie
        for nl in namelists:
            body += struct.pack(">I", len(nl)) + nl
        body += b"\x00\x00"  # first_kex_packet_follows + reserved bool
        body += b"\x00\x00\x00\x00"  # uint32 reserved
        return body

    def test_parses_pqc_kex_advertisement(self):
        payload = self._build_kexinit(
            [
                b"mlkem768x25519-sha256,curve25519-sha256",
                b"ssh-ed25519,rsa-sha2-512",
                b"chacha20-poly1305@openssh.com",
                b"chacha20-poly1305@openssh.com",
                b"hmac-sha2-256-etm@openssh.com",
                b"hmac-sha2-256-etm@openssh.com",
                b"none",
                b"none",
                b"",
                b"",
            ]
        )
        parsed = _parse_ssh_kexinit(payload)
        assert parsed["kex_algorithms"] == ["mlkem768x25519-sha256", "curve25519-sha256"]
        assert parsed["server_host_key_algorithms"] == ["ssh-ed25519", "rsa-sha2-512"]
        assert parsed["_malformed"] == []

    def test_parses_classical_only_advertisement(self):
        payload = self._build_kexinit(
            [
                b"curve25519-sha256,ecdh-sha2-nistp256",
                b"ssh-rsa",
                b"",
                b"",
                b"",
                b"",
                b"",
                b"",
                b"",
                b"",
            ]
        )
        parsed = _parse_ssh_kexinit(payload)
        assert "mlkem768x25519-sha256" not in parsed["kex_algorithms"]

    def test_rejects_short_payload(self):
        with pytest.raises(ValueError, match="kexinit_payload_too_short"):
            _parse_ssh_kexinit(b"\x14")

    def test_rejects_wrong_message_type(self):
        bad = bytes([21]) + b"\x00" * 16 + b"\x00" * 4 * 10
        with pytest.raises(ValueError, match="kexinit_unexpected_msg_type_21"):
            _parse_ssh_kexinit(bad)

    def test_rejects_oversized_namelist(self):
        # Length field claims 9999999 bytes; truncated payload.
        body = bytes([20]) + b"\x00" * 16 + struct.pack(">I", 9999999)
        with pytest.raises(ValueError, match="kexinit_namelist_0_oversized"):
            _parse_ssh_kexinit(body)

    def test_drops_malformed_names_into_underscore_malformed(self):
        # F-SEC-1 (CWE-117): server advertises a malformed name; parser must
        # drop it and record a hex prefix in `_malformed` rather than letting
        # the bytes flow into log lines.
        injected = b"mlkem768x25519-sha256,bad\nname"
        payload = self._build_kexinit([injected, b"", b"", b"", b"", b"", b"", b"", b"", b""])
        parsed = _parse_ssh_kexinit(payload)
        assert parsed["kex_algorithms"] == ["mlkem768x25519-sha256"]
        assert any(m.startswith("namelist0:") for m in parsed["_malformed"]), parsed["_malformed"]


class TestClassifyAndVerdict:
    def test_classify_splits_pqc_and_classical(self):
        pqc, classical = _classify_ssh_kex(
            ["mlkem768x25519-sha256", "curve25519-sha256", "ecdh-sha2-nistp256"]
        )
        assert pqc == ["mlkem768x25519-sha256"]
        assert classical == ["curve25519-sha256", "ecdh-sha2-nistp256"]

    def test_provisional_verdict_pqc_ready_when_standardized(self):
        verdict: Verdict = _provisional_verdict_ssh(["mlkem768x25519-sha256"])
        assert verdict == "pqc_ready"

    def test_provisional_verdict_classical_only_when_empty(self):
        assert _provisional_verdict_ssh([]) == "classical_only"


# ---------- End-to-end SSH probe tests with a fake server --------------------


class _FakeSshServer:
    """Minimal stub that listens on localhost and replies with a canned KEXINIT.

    Used to exercise ``PqcLibrary.ssh_pqc_scan`` without external network.
    Each instance handles ONE connection then shuts down.
    """

    def __init__(self, mode: str = "valid_pqc"):
        self.mode = mode
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", 0))
        self._server.listen(1)
        self._server.settimeout(5)
        self.host, self.port = self._server.getsockname()
        self.connection_count = 0
        self._thread: threading.Thread | None = None

    def __enter__(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        try:
            self._server.close()
        except OSError:
            pass

    @staticmethod
    def _build_kexinit_packet(payload: bytes) -> bytes:
        # Per RFC 4253 §6.1: packet_length, padding_length, payload, padding.
        # block_size for unencrypted = 8.
        block_size = 8
        # length we encode = padding_length(1) + payload + padding
        # total packet_length+payload+padding must be multiple of block_size,
        # and packet_length itself is uint32, not part of the multiple.
        padding_length = block_size - ((1 + len(payload)) % block_size)
        if padding_length < 4:
            padding_length += block_size
        body = bytes([padding_length]) + payload + b"\x00" * padding_length
        return struct.pack(">I", len(body)) + body

    @staticmethod
    def _build_kexinit_payload(kex_names: bytes) -> bytes:
        body = bytes([20]) + b"\x00" * 16
        namelists = [
            kex_names,
            b"ssh-ed25519",
            b"chacha20-poly1305@openssh.com",
            b"chacha20-poly1305@openssh.com",
            b"hmac-sha2-256-etm@openssh.com",
            b"hmac-sha2-256-etm@openssh.com",
            b"none",
            b"none",
            b"",
            b"",
        ]
        for nl in namelists:
            body += struct.pack(">I", len(nl)) + nl
        body += b"\x00\x00\x00\x00\x00\x00"
        return body

    def _run(self):
        try:
            client_sock, _ = self._server.accept()
            self.connection_count += 1
            try:
                client_sock.settimeout(5)
                if self.mode == "tcp_accept_then_silent":
                    # Hold the connection without sending banner — exercise client
                    # banner_timeout path.
                    try:
                        time.sleep(2)
                    except Exception:
                        pass
                    return
                if self.mode == "garbage_banner":
                    client_sock.sendall(b"\xff\x00not-ssh\r\n")
                    return
                if self.mode == "oversized_banner":
                    client_sock.sendall(b"X" * 1000)
                    return
                # Send banner, then try to read client banner (drain), then send KEXINIT.
                client_sock.sendall(b"SSH-2.0-FakeServerForPqcTests\r\n")
                # Drain client banner up to \n.
                drained = b""
                while b"\n" not in drained and len(drained) < 512:
                    chunk = client_sock.recv(64)
                    if not chunk:
                        break
                    drained += chunk
                if self.mode == "valid_pqc":
                    payload = self._build_kexinit_payload(
                        b"mlkem768x25519-sha256,curve25519-sha256"
                    )
                elif self.mode == "valid_pqc_hybrid_legacy":
                    payload = self._build_kexinit_payload(
                        b"sntrup761x25519-sha512@openssh.com,curve25519-sha256"
                    )
                elif self.mode == "classical_only":
                    payload = self._build_kexinit_payload(b"curve25519-sha256,ecdh-sha2-nistp256")
                elif self.mode == "injected_name":
                    # F-SEC-1 abuse case
                    payload = self._build_kexinit_payload(b"mlkem768x25519-sha256,bad\nname")
                else:
                    payload = self._build_kexinit_payload(b"curve25519-sha256")
                client_sock.sendall(self._build_kexinit_packet(payload))
            finally:
                try:
                    client_sock.close()
                except OSError:
                    pass
        except (OSError, socket.timeout):
            pass


@pytest.fixture
def pqc_library() -> PqcLibrary:
    return PqcLibrary()


@pytest.fixture
def pqc_engine() -> PqcEngine:
    return PqcEngine()


def _fd_count() -> int:
    """Count open FDs for the current process; cross-platform-ish.

    Used by FD-leak BDD scenarios (F-SEC-3 / CWE-404).
    """
    try:
        import psutil  # type: ignore[import-untyped]

        return psutil.Process().num_fds()
    except ImportError:
        # macOS without psutil — best-effort via /dev/fd if present, else /proc/self/fd.
        import os

        for path in ("/dev/fd", "/proc/self/fd"):
            if os.path.isdir(path):
                return len(os.listdir(path))
        return -1


class TestSshProbeAgainstFakeServer:
    def test_pqc_ready_when_server_advertises_mlkem(self, pqc_library):
        with _FakeSshServer(mode="valid_pqc") as srv:
            result = pqc_library.ssh_pqc_scan(srv.host, srv.port, timeout=3)
        assert result["scan_succeeded"] is True
        assert result["verdict"] == "pqc_ready"
        assert "mlkem768x25519-sha256" in result["ssh_pqc_kex_advertised"]
        assert "curve25519-sha256" in result["ssh_classical_kex_advertised"]
        assert result["errors"] == []

    def test_pqc_ready_when_server_advertises_sntrup761(self, pqc_library):
        with _FakeSshServer(mode="valid_pqc_hybrid_legacy") as srv:
            result = pqc_library.ssh_pqc_scan(srv.host, srv.port, timeout=3)
        assert result["verdict"] == "pqc_ready"
        assert "sntrup761x25519-sha512@openssh.com" in result["ssh_pqc_kex_advertised"]

    def test_classical_only_when_no_pqc_advertised(self, pqc_library):
        with _FakeSshServer(mode="classical_only") as srv:
            result = pqc_library.ssh_pqc_scan(srv.host, srv.port, timeout=3)
        assert result["scan_succeeded"] is True
        assert result["verdict"] == "classical_only"
        assert result["ssh_pqc_kex_advertised"] == []
        assert "curve25519-sha256" in result["ssh_classical_kex_advertised"]

    def test_tcp_refused_returns_unknown_with_error(self, pqc_library):
        # Pick a port that is almost certainly closed (49151 is end of registered range).
        result = pqc_library.ssh_pqc_scan("127.0.0.1", 1, timeout=2)
        assert result["scan_succeeded"] is False
        assert result["verdict"] == "unknown"
        assert any("tcp_refused" in e or "tcp_error" in e for e in result["errors"])

    def test_garbage_banner_recorded_as_error(self, pqc_library):
        with _FakeSshServer(mode="garbage_banner") as srv:
            result = pqc_library.ssh_pqc_scan(srv.host, srv.port, timeout=3)
        assert result["scan_succeeded"] is False
        assert any("malformed_banner" in e for e in result["errors"])

    def test_oversized_banner_capped(self, pqc_library):
        # F-SEC bounded resource (RFC 4253 §4.2).
        with _FakeSshServer(mode="oversized_banner") as srv:
            result = pqc_library.ssh_pqc_scan(srv.host, srv.port, timeout=3)
        assert result["scan_succeeded"] is False
        assert any("banner_overflow" in e for e in result["errors"])

    def test_malformed_algorithm_name_dropped_with_hex_prefix(self, pqc_library):
        # F-SEC-1 CWE-117: server's malformed name string never reaches log line raw.
        with _FakeSshServer(mode="injected_name") as srv:
            result = pqc_library.ssh_pqc_scan(srv.host, srv.port, timeout=3)
        assert result["scan_succeeded"] is True
        assert "mlkem768x25519-sha256" in result["ssh_pqc_kex_advertised"]
        assert any("malformed_algorithm_name" in e for e in result["errors"])
        # The newline-injected bytes must NOT appear in any field.
        for field in ["ssh_pqc_kex_advertised", "ssh_classical_kex_advertised"]:
            for entry in result.get(field) or []:
                assert "\n" not in entry
                assert "bad" != entry  # not the injected fragment


class TestFdLeakInvariant:
    """F-SEC-3 / CWE-404 — every probe code path closes its socket."""

    @pytest.mark.parametrize(
        "mode",
        ["valid_pqc", "classical_only", "garbage_banner", "oversized_banner", "injected_name"],
    )
    def test_fd_count_stable_across_probe(self, pqc_library, mode):
        before = _fd_count()
        if before < 0:
            pytest.skip("FD count not observable on this platform")
        with _FakeSshServer(mode=mode) as srv:
            pqc_library.ssh_pqc_scan(srv.host, srv.port, timeout=3)
        after = _fd_count()
        # Allow ±1 jitter for thread teardown timing on some platforms.
        assert abs(after - before) <= 1, f"FD leak: {before} -> {after} for mode={mode}"

    def test_fd_count_stable_on_tcp_refused(self, pqc_library):
        before = _fd_count()
        if before < 0:
            pytest.skip("FD count not observable on this platform")
        pqc_library.ssh_pqc_scan("127.0.0.1", 1, timeout=2)
        after = _fd_count()
        assert abs(after - before) <= 1


class TestLibraryNeverRaises:
    """F-ENG-1 — library catches every recoverable network exception so the
    framework's BaseEngine.run retry loop is a no-op for probe failures."""

    def _iter_pathological_targets(self) -> Iterator[tuple[str, int]]:
        yield ("127.0.0.1", 1)  # closed port
        yield ("127.0.0.1", 0)  # invalid port
        yield ("0.0.0.0", 22)  # unroutable from the scanner

    def test_no_exception_escapes_for_pathological_targets(self, pqc_library):
        for host, port in self._iter_pathological_targets():
            try:
                result = pqc_library.ssh_pqc_scan(host, port, timeout=1)
            except Exception as exc:  # pragma: no cover — failure path
                pytest.fail(f"ssh_pqc_scan raised {type(exc).__name__}: {exc}")
            assert isinstance(result, dict)
            assert result["verdict"] == "unknown"
            assert result["scan_succeeded"] is False


class TestPqcEngineConditionsResults:
    def test_apply_extra_data_populates_conditions_results_on_success(self, pqc_engine):
        sub_step = {"response": {"conditions": {}, "condition_type": "or"}}
        response = {
            "host": "ex.com",
            "port": 22,
            "service": "ssh",
            "scan_succeeded": True,
            "verdict": "pqc_ready",
            "compliance_notes": "ok",
            "ssh_pqc_kex_advertised": ["mlkem768x25519-sha256"],
        }
        pqc_engine.apply_extra_data(sub_step, response)
        assert sub_step["response"]["conditions_results"] == {
            "host": "ex.com",
            "port": 22,
            "service": "ssh",
            "verdict": "pqc_ready",
            "compliance_notes": "ok",
            "advertised_pqc": ["mlkem768x25519-sha256"],
        }

    def test_apply_extra_data_empty_on_failure(self, pqc_engine):
        sub_step = {"response": {"conditions": {}, "condition_type": "or"}}
        response = {"scan_succeeded": False, "verdict": "unknown"}
        pqc_engine.apply_extra_data(sub_step, response)
        assert sub_step["response"]["conditions_results"] == []

    def test_apply_extra_data_handles_non_dict_response(self, pqc_engine):
        sub_step = {"response": {"conditions": {}, "condition_type": "or"}}
        pqc_engine.apply_extra_data(sub_step, [])
        assert sub_step["response"]["conditions_results"] == []
