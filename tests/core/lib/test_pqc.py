"""Unit + integration tests for ``nettacker.core.lib.pqc`` (M1 SSH + M2 TLS)."""

import random
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
    _build_tls13_client_hello,
    _classify_ssh_kex,
    _classify_tls_groups,
    _parse_ssh_kexinit,
    _parse_tls13_server_response,
    _provisional_verdict_ssh,
    _provisional_verdict_tls,
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

    def test_tls_table_within_v1_cap(self):
        # M2 + critique F-CEO-1 — table cap ≤8.
        assert len(TLS_PQC_NAMED_GROUPS) <= 8

    def test_tls_table_includes_required_groups(self):
        # F-CEO-1: must include MLKEM1024 for honest CNSA 2.0 mapping.
        names = {entry["name"] for entry in TLS_PQC_NAMED_GROUPS.values()}
        assert "MLKEM768" in names
        assert "MLKEM1024" in names
        assert "X25519MLKEM768" in names
        assert "SecP384r1MLKEM1024" in names

    def test_tls_table_entries_well_formed(self):
        # F-ENG-3: every entry must include key_share_bytes from the IETF-pinned table.
        required = {"name", "kind", "status", "key_share_bytes", "source"}
        for cp, entry in TLS_PQC_NAMED_GROUPS.items():
            assert required.issubset(entry.keys()), (
                f"codepoint {cp:#x} missing keys: {required - set(entry.keys())}"
            )
            assert entry["kind"] in {"pure_pq", "hybrid"}
            assert entry["status"] in {"standardized", "draft", "experimental"}
            assert entry["key_share_bytes"] > 0
            assert 0 <= cp <= 0xFFFF

    @pytest.mark.parametrize(
        "codepoint,expected_bytes",
        [
            (0x0201, 1184),  # MLKEM768
            (0x0202, 1568),  # MLKEM1024
            (0x11EB, 1249),  # SecP256r1MLKEM768
            (0x11EC, 1216),  # X25519MLKEM768
            (0x11ED, 1665),  # SecP384r1MLKEM1024
        ],
    )
    def test_tls_table_key_share_lengths_match_ietf_pinned(self, codepoint, expected_bytes):
        """F-ENG-3 — key_share_bytes pinned to IETF drafts."""
        assert TLS_PQC_NAMED_GROUPS[codepoint]["key_share_bytes"] == expected_bytes


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


# ---------- M2: TLS 1.3 ClientHello + parser tests ---------------------------


class TestBuildClientHello:
    """Structural assertions on the emitted ClientHello bytes.

    We assert the *shape* (record header, handshake header, lengths,
    extension presence) rather than golden snapshots, because golden
    snapshots are brittle (they catch any byte change but say nothing
    about correctness). A future TLS implementer can read these assertions
    and confirm RFC 8446 §4.1.2 compliance.
    """

    @pytest.mark.parametrize(
        "codepoint",
        [0x0201, 0x0202, 0x11EB, 0x11EC, 0x11ED],
    )
    def test_clienthello_well_formed_for_each_pqc_group(self, codepoint):
        ch = _build_tls13_client_hello(
            codepoint,
            "example.com",
            client_random=b"\x00" * 32,
            legacy_session_id=b"\x01" * 32,
        )
        # Record header: type=22 handshake, legacy_record_version=0x0303
        assert ch[0] == 22
        assert ch[1:3] == b"\x03\x03"
        record_length = int.from_bytes(ch[3:5], "big")
        assert 5 + record_length == len(ch), "record length must match buffer"
        # Handshake header: msg_type=1 ClientHello, uint24 length
        assert ch[5] == 1
        hs_length = int.from_bytes(ch[6:9], "big")
        assert 9 + hs_length == len(ch), "handshake length must match"
        # ClientHello body: legacy_version=0x0303, then random[32], then sid_len(1)
        assert ch[9:11] == b"\x03\x03"
        assert ch[11:43] == b"\x00" * 32  # the client_random we passed
        assert ch[43] == 32  # sid len
        assert ch[44:76] == b"\x01" * 32

    def test_clienthello_under_paranoid_cap(self):
        # F-ENG-3 + M2 invariant — even SecP384r1MLKEM1024 must fit under cap.
        for cp in TLS_PQC_NAMED_GROUPS:
            ch = _build_tls13_client_hello(
                cp, "example.com", client_random=b"\x00" * 32, legacy_session_id=b""
            )
            from nettacker.core.lib.pqc import _TLS_CLIENT_HELLO_MAX

            assert len(ch) <= _TLS_CLIENT_HELLO_MAX, (
                f"ClientHello for {TLS_PQC_NAMED_GROUPS[cp]['name']} = {len(ch)} bytes "
                f"exceeded paranoid cap of {_TLS_CLIENT_HELLO_MAX}"
            )

    def test_clienthello_includes_target_group_in_supported_groups(self):
        # Search for the supported_groups extension and confirm our group is there.
        ch = _build_tls13_client_hello(
            0x11EC,
            "example.com",
            client_random=b"\x00" * 32,
            legacy_session_id=b"\x01" * 32,
        )
        # supported_groups = 0x000A. Look for the 4-byte extension header.
        # Note: this is a structural / functional test — we accept that 0x000A
        # could appear inside other fields by coincidence, but the explicit
        # supported_groups extension immediately follows supported_versions.
        assert b"\x00\x0a" in ch  # extension type
        # Our codepoint 0x11EC must appear:
        assert b"\x11\xec" in ch

    def test_clienthello_includes_sni(self):
        ch = _build_tls13_client_hello(
            0x11EC,
            "owasp.org",
            client_random=b"\x00" * 32,
            legacy_session_id=b"\x01" * 32,
        )
        assert b"owasp.org" in ch

    def test_clienthello_key_share_payload_zero_filled(self):
        # The PQC key_share is a fixed all-zero buffer of correct length.
        ch = _build_tls13_client_hello(
            0x0201,  # MLKEM768 = 1184 byte key_share
            "example.com",
            client_random=b"\x33" * 32,
            legacy_session_id=b"\x55" * 32,
        )
        # Look for a run of 1184 zero bytes — only place this can appear is
        # the key_share payload (random and sid are non-zero).
        assert (b"\x00" * 1184) in ch

    def test_clienthello_rejects_unknown_codepoint(self):
        with pytest.raises(ValueError, match="unknown_pqc_group_codepoint"):
            _build_tls13_client_hello(0xFFFE, "example.com")

    def test_clienthello_rejects_wrong_random_length(self):
        with pytest.raises(ValueError, match="client_random must be 32 bytes"):
            _build_tls13_client_hello(0x11EC, "example.com", client_random=b"\x00" * 16)


class TestParseTls13ServerResponse:
    """F-SEC-2 invariant: parser is total; no exception escapes."""

    @staticmethod
    def _build_server_hello(selected_group: int | None, *, hrr: bool = False) -> bytes:
        from nettacker.core.lib.pqc import _TLS_HRR_RANDOM

        random_bytes = _TLS_HRR_RANDOM if hrr else b"\x42" * 32
        sid = b"\x99" * 32
        cipher_suite = b"\x13\x01"
        compress = b"\x00"
        if selected_group is not None:
            ks_ext = struct.pack(">HH", 51, 2) + struct.pack(">H", selected_group)
        else:
            ks_ext = b""
        ext_blob = ks_ext
        sh_body = (
            b"\x03\x03"
            + random_bytes
            + struct.pack(">B", len(sid))
            + sid
            + cipher_suite
            + compress
            + struct.pack(">H", len(ext_blob))
            + ext_blob
        )
        hs = struct.pack(">B", 2) + struct.pack(">I", len(sh_body))[1:] + sh_body
        return struct.pack(">BHH", 22, 0x0303, len(hs)) + hs

    def test_parses_server_hello_with_selected_group(self):
        record = self._build_server_hello(0x11EC)
        result = _parse_tls13_server_response(record)
        assert result == {"kind": "server_hello", "selected_group": 0x11EC, "is_hrr": False}

    def test_detects_hello_retry_request(self):
        record = self._build_server_hello(0x11EC, hrr=True)
        result = _parse_tls13_server_response(record)
        assert result["kind"] == "server_hello"
        assert result["is_hrr"] is True
        assert result["selected_group"] == 0x11EC

    def test_parses_handshake_failure_alert(self):
        record = struct.pack(">BHH", 21, 0x0303, 2) + b"\x02\x28"  # fatal handshake_failure(40)
        result = _parse_tls13_server_response(record)
        assert result == {"kind": "alert", "level": 2, "description": 40}

    def test_parses_decode_error_alert(self):
        record = struct.pack(">BHH", 21, 0x0303, 2) + b"\x02\x32"  # decode_error(50)
        result = _parse_tls13_server_response(record)
        assert result == {"kind": "alert", "level": 2, "description": 50}

    @pytest.mark.parametrize(
        "buf,expected_reason_substring",
        [
            (b"", "record_header_truncated"),
            (b"\xff", "record_header_truncated"),
            (b"\xff\xff\xff", "record_header_truncated"),
            (b"\x16\x03\x03\xff\xff", "record_length_exceeds_cap"),
            (struct.pack(">BHH", 21, 0x0303, 1) + b"\x02", "alert_body_truncated"),
            (struct.pack(">BHH", 22, 0x0303, 0), "handshake_header_truncated"),
        ],
    )
    def test_malformed_inputs_return_tagged_malformed(self, buf, expected_reason_substring):
        result = _parse_tls13_server_response(buf)
        assert result["kind"] == "malformed"
        assert expected_reason_substring in result["reason"]

    def test_unknown_record_type_tagged(self):
        record = struct.pack(">BHH", 99, 0x0303, 0)  # unknown record_type=99
        result = _parse_tls13_server_response(record)
        assert result == {"kind": "unknown_record", "type": 99}


class TestParserIsTotalUnderFuzzing:
    """F-SEC-2 / CWE-787 / CWE-770 — 100 randomly-mutated inputs; no exception escapes.

    The seed is fixed so failures reproduce. Any failure is a real parser bug.
    """

    SEED = 0xDEADBEEF
    ITERATIONS = 100

    def _seed_input(self) -> bytes:
        # Start from a valid-shape ServerHello, then mutate.
        record = TestParseTls13ServerResponse._build_server_hello(0x11EC)
        return record

    def test_no_exception_escapes_for_random_byte_mutations(self):
        rng = random.Random(self.SEED)
        seed = self._seed_input()
        for _ in range(self.ITERATIONS):
            mutated = bytearray(seed)
            # 1-5 bit-flip mutations
            for _flip in range(rng.randint(1, 5)):
                if not mutated:
                    break
                idx = rng.randrange(len(mutated))
                mutated[idx] ^= 1 << rng.randrange(8)
            # 0-2 truncations
            for _trunc in range(rng.randint(0, 2)):
                if mutated:
                    cut = rng.randrange(len(mutated))
                    mutated = mutated[:cut]
            # 0-1 random insertion
            if rng.random() < 0.5 and mutated:
                idx = rng.randrange(len(mutated) + 1)
                mutated[idx:idx] = bytes([rng.randrange(256) for _ in range(rng.randint(1, 8))])
            try:
                result = _parse_tls13_server_response(bytes(mutated))
            except Exception as exc:  # pragma: no cover — F-SEC-2 fail
                pytest.fail(
                    f"parser raised {type(exc).__name__} on input "
                    f"{bytes(mutated)[:40].hex()}...: {exc}"
                )
            assert isinstance(result, dict)
            assert "kind" in result
            assert result["kind"] in {"server_hello", "alert", "unknown_record", "malformed"}

    def test_no_exception_on_pure_random_bytes(self):
        rng = random.Random(self.SEED + 1)
        for _ in range(self.ITERATIONS):
            length = rng.randint(0, 200)
            buf = bytes(rng.randrange(256) for _ in range(length))
            try:
                result = _parse_tls13_server_response(buf)
            except Exception as exc:  # pragma: no cover
                pytest.fail(f"parser raised on pure-random input ({length} bytes): {exc}")
            assert result["kind"] in {"server_hello", "alert", "unknown_record", "malformed"}


class TestClassifyAndVerdictTls:
    def test_classify_splits_pqc_and_classical(self):
        pqc, classical = _classify_tls_groups([0x11EC, 0x001D, 0x0017])  # PQC, x25519, secp256r1
        assert pqc == ["X25519MLKEM768"]
        assert classical == [0x001D, 0x0017]

    def test_provisional_verdict_pqc_ready(self):
        assert _provisional_verdict_tls(["X25519MLKEM768"]) == "pqc_ready"
        assert _provisional_verdict_tls(["MLKEM1024"]) == "pqc_ready"

    def test_provisional_verdict_classical_only_when_empty(self):
        assert _provisional_verdict_tls([]) == "classical_only"


# ---------- TLS probe e2e against fake server --------------------------------


class _FakeTlsServer:
    """Listen on localhost; for each accepted connection, replay a canned TLS
    record once the client's ClientHello is received.

    Modes correspond to the BDD scenarios in the M2 contract.
    """

    def __init__(self, mode: str, selected_group: int | None = None):
        self.mode = mode
        self.selected_group = selected_group
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self._sock.settimeout(5)
        self.host, self.port = self._sock.getsockname()
        self.connection_count = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass

    def _drain_clienthello(self, c: socket.socket) -> None:
        # Read ≥ TLS record header so we know the client said something.
        # We don't fully parse — just consume until we have at least one record.
        try:
            buf = b""
            while len(buf) < 5:
                chunk = c.recv(4096)
                if not chunk:
                    return
                buf += chunk
            if len(buf) >= 5:
                expect = int.from_bytes(buf[3:5], "big")
                while len(buf) < 5 + expect:
                    chunk = c.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
        except (OSError, socket.timeout):
            pass

    def _build_server_hello_record(self) -> bytes:
        return TestParseTls13ServerResponse._build_server_hello(self.selected_group)

    def _build_alert(self, description: int) -> bytes:
        return struct.pack(">BHH", 21, 0x0303, 2) + bytes([2, description])

    def _run(self):
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()
            except (OSError, socket.timeout):
                return
            self.connection_count += 1
            try:
                client.settimeout(5)
                if self.mode == "silent_after_accept":
                    time.sleep(2)
                    continue
                self._drain_clienthello(client)
                if self.mode == "select_group":
                    client.sendall(self._build_server_hello_record())
                elif self.mode == "handshake_failure":
                    client.sendall(self._build_alert(40))
                elif self.mode == "decode_error":
                    client.sendall(self._build_alert(50))
                elif self.mode == "oversized_record":
                    # Claim a large length but send little — exercises
                    # parser robustness + recv cap.
                    client.sendall(struct.pack(">BHH", 22, 0x0303, 16383) + b"\x00" * 16383)
                elif self.mode == "unknown_record":
                    client.sendall(struct.pack(">BHH", 99, 0x0303, 0))
                elif self.mode == "garbage":
                    client.sendall(b"\xff" * 200)
                elif self.mode == "tcp_close_immediate":
                    pass  # close without sending
                else:
                    client.sendall(self._build_server_hello_record())
            finally:
                try:
                    client.close()
                except OSError:
                    pass


@pytest.fixture
def fd_baseline():
    return _fd_count()


class TestTlsProbeAgainstFakeServer:
    def test_pqc_ready_when_server_selects_x25519mlkem768(self, pqc_library):
        with _FakeTlsServer(mode="select_group", selected_group=0x11EC) as srv:
            result = pqc_library.tls_pqc_scan(srv.host, srv.port, timeout=3)
        assert result["scan_succeeded"] is True
        assert result["verdict"] == "pqc_ready"
        assert "X25519MLKEM768" in result["tls_pqc_groups_advertised"]

    def test_pqc_ready_when_server_selects_mlkem1024(self, pqc_library):
        # F-CEO-1: mlkem1024 advertised → CNSA-2.0-compliant note in M3.
        with _FakeTlsServer(mode="select_group", selected_group=0x0202) as srv:
            result = pqc_library.tls_pqc_scan(srv.host, srv.port, timeout=3)
        assert result["scan_succeeded"] is True
        assert result["verdict"] == "pqc_ready"
        assert "MLKEM1024" in result["tls_pqc_groups_advertised"]
        assert "CNSA 2.0 ML-KEM-1024" in result["compliance_notes"]

    def test_classical_only_when_handshake_failure_for_every_group(self, pqc_library):
        with _FakeTlsServer(mode="handshake_failure") as srv:
            result = pqc_library.tls_pqc_scan(srv.host, srv.port, timeout=3)
        # Every probe got a clean alert — server responded but never advertised PQC.
        assert result["scan_succeeded"] is True
        assert result["verdict"] == "classical_only"
        assert result["tls_pqc_groups_advertised"] == []
        # Clean handshake_failure does NOT generate per-group errors.
        assert all("decode_error" not in e for e in result["errors"])

    def test_decode_error_recorded_per_group(self, pqc_library):
        # F-ENG-3: decode_error hints our key_share length might be wrong.
        with _FakeTlsServer(mode="decode_error") as srv:
            result = pqc_library.tls_pqc_scan(srv.host, srv.port, timeout=3)
        assert result["scan_succeeded"] is True
        assert result["verdict"] == "classical_only"  # nothing advertised
        # Every group probed should have a decode_error entry.
        for entry in TLS_PQC_NAMED_GROUPS.values():
            assert any(f"decode_error_for_{entry['name']}" in e for e in result["errors"]), (
                f"missing decode_error for {entry['name']}"
            )

    def test_tcp_refused_returns_unknown_with_transport_failed(self, pqc_library):
        # No fake server — connect to a closed port.
        result = pqc_library.tls_pqc_scan("127.0.0.1", 1, timeout=2)
        assert result["scan_succeeded"] is False
        assert result["verdict"] == "unknown"
        assert "tcp_refused" in result["errors"]

    def test_oversized_record_captured_with_recv_cap(self, pqc_library):
        # tm-pqc-compliance-scanner-abuse-2 — recv() bounded at _TLS_RECORD_MAX.
        with _FakeTlsServer(mode="oversized_record") as srv:
            result = pqc_library.tls_pqc_scan(srv.host, srv.port, timeout=3)
        # We get *some* response (possibly malformed parse). The key invariant
        # is that the call returns and didn't OOM.
        assert isinstance(result, dict)
        assert result["scan_succeeded"] in {True, False}

    def test_probe_loop_makes_one_connection_per_group(self, pqc_library):
        # Resource bound: ≤ len(TLS_PQC_NAMED_GROUPS) connections per (host, port).
        with _FakeTlsServer(mode="handshake_failure") as srv:
            pqc_library.tls_pqc_scan(srv.host, srv.port, timeout=3)
            time.sleep(0.05)  # let the server thread tally
        assert srv.connection_count == len(TLS_PQC_NAMED_GROUPS)


class TestTlsFdLeakInvariant:
    """F-SEC-3 / CWE-404 across TLS probe paths."""

    @pytest.mark.parametrize(
        "mode",
        ["select_group", "handshake_failure", "decode_error", "garbage", "tcp_close_immediate"],
    )
    def test_fd_count_stable_across_tls_probe(self, pqc_library, mode):
        before = _fd_count()
        if before < 0:
            pytest.skip("FD count not observable on this platform")
        with _FakeTlsServer(mode=mode, selected_group=0x11EC) as srv:
            pqc_library.tls_pqc_scan(srv.host, srv.port, timeout=2)
            time.sleep(0.05)
        after = _fd_count()
        # Allow ±2 jitter for thread teardown across many connections (8 per probe).
        assert abs(after - before) <= 2, f"TLS FD leak: {before} -> {after} for mode={mode}"

    def test_tls_fd_count_stable_on_tcp_refused(self, pqc_library):
        before = _fd_count()
        if before < 0:
            pytest.skip("FD count not observable on this platform")
        pqc_library.tls_pqc_scan("127.0.0.1", 1, timeout=1)
        after = _fd_count()
        assert abs(after - before) <= 1


class TestTlsLibraryNeverRaises:
    def test_no_exception_for_pathological_targets(self, pqc_library):
        for host, port in [("127.0.0.1", 1), ("127.0.0.1", 0), ("0.0.0.0", 443)]:
            try:
                result = pqc_library.tls_pqc_scan(host, port, timeout=1)
            except Exception as exc:  # pragma: no cover
                pytest.fail(f"tls_pqc_scan raised {type(exc).__name__}: {exc}")
            assert isinstance(result, dict)
            assert result["scan_succeeded"] is False
            assert result["verdict"] == "unknown"
