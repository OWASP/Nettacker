import re
from unittest.mock import patch

from nettacker.probing.engine import Interpret, Printable, ProbeEngine, expand_template
from nettacker.probing.loader import Probe, Signature, version_details


def _regex_match(pattern, data):
    return re.search(pattern, data)


class TestInterpret:
    def test_big_endian(self):
        assert Interpret(b"\x00\x01", ">") == 1

    def test_little_endian(self):
        assert Interpret(b"\x01\x00", "<") == 1

    def test_accepts_string_input(self):
        assert Interpret("\x00\x01", ">") == 1

    def test_truncates_to_eight_bytes(self):
        assert Interpret(b"\xff" * 16, ">") == Interpret(b"\xff" * 8, ">")


class TestPrintable:
    def test_strips_nulls_and_non_printables(self):
        assert Printable(b"AB\x00\xffC") == "ABC"

    def test_accepts_str_input(self):
        assert Printable("AB\x00C") == "ABC"


class TestExpandTemplate:
    def test_place_substitution(self):
        match = _regex_match(rb"(\w+)-(\w+)", b"foo-bar")
        assert expand_template("$1/$2", match) == "foo/bar"

    def test_printable_substitution(self):
        match = _regex_match(rb"(.+)", b"OpenSSH\x00")
        assert expand_template("$P(1)", match) == "OpenSSH"

    def test_subst_substitution(self):
        match = _regex_match(rb"(.+)", b"a-b-c")
        assert expand_template('$SUBST(1, "-", ".")', match) == "a.b.c"

    def test_interpret_substitution(self):
        match = _regex_match(rb"(..)", b"\x00\x01")
        assert expand_template("$I(1,>)", match) == "1"

    def test_missing_group_returns_empty_string(self):
        match = _regex_match(rb"(\w+)", b"foo")
        assert expand_template("$2", match) == ""


class TestProbeEngineFiltering:
    def _make_probe(self, name, protocol, ports=None, sslports=None):
        return Probe(
            name=name,
            protocol=protocol,
            ports=ports or [],
            sslports=sslports or [],
            fallbacks=[],
            probe_string="",
            Signatures=[],
        )

    def test_get_probes_for_port_matches_protocol_and_port(self):
        probes = {
            "HTTP": self._make_probe("HTTP", "tcp", ports=[80]),
            "DNS": self._make_probe("DNS", "udp", ports=[53]),
            "NULL": self._make_probe("NULL", "tcp"),
        }
        engine = ProbeEngine(port=80, protocol="tcp", host="127.0.0.1", probes_by_name=probes)
        selected = {p.name for p in engine.get_probes_for_port()}
        assert selected == {"HTTP", "NULL"}

    def test_get_probes_for_port_excludes_wrong_port(self):
        probes = {"HTTP": self._make_probe("HTTP", "tcp", ports=[80])}
        engine = ProbeEngine(port=8080, protocol="tcp", host="127.0.0.1", probes_by_name=probes)
        assert engine.get_probes_for_port() == []

    def test_get_probes_for_sslport(self):
        probes = {
            "TLS_HTTP": self._make_probe("TLS_HTTP", "tcp", sslports=[443]),
            "NULL": self._make_probe("NULL", "tcp"),
        }
        engine = ProbeEngine(port=443, protocol="tcp", host="127.0.0.1", probes_by_name=probes)
        selected = {p.name for p in engine.get_probes_for_sslport()}
        assert selected == {"TLS_HTTP", "NULL"}


class TestMatchResponse:
    def _make_signature(self, sig_type="match", service="ssh", regex=b"SSH-([\\d.]+)"):
        version = version_details(
            raw="",
            version_template="$1",
            product="OpenSSH",
            info="",
            hostname="",
            operating_device="",
            device_type="",
            cpe_service="",
            cpe_os="",
            cpe_h="",
        )
        return Signature(
            service=service,
            regex=re.compile(regex),
            sig_type=sig_type,
            version_details=version,
        )

    def test_none_response_does_not_match(self):
        engine = ProbeEngine(port=22, protocol="tcp", host="127.0.0.1", probes_by_name={})
        result = engine.Match_response(None, self._make_signature())
        assert result["status"] is False

    def test_matching_response_extracts_version(self):
        engine = ProbeEngine(port=22, protocol="tcp", host="127.0.0.1", probes_by_name={})
        signature = self._make_signature()
        result = engine.Match_response(b"SSH-2.0\r\n", signature)
        assert result["status"] is True
        assert result["result"].version_template == "2.0"
        assert result["result"].product == "OpenSSH"

    def test_non_matching_response(self):
        engine = ProbeEngine(port=22, protocol="tcp", host="127.0.0.1", probes_by_name={})
        signature = self._make_signature()
        result = engine.Match_response(b"HTTP/1.1 200 OK\r\n", signature)
        assert result["status"] is False


class TestProbeSequentially:
    def _make_probe_with_signature(self):
        version = version_details(raw="", version_template="$1", product="OpenSSH")
        signature = Signature(
            service="ssh",
            regex=re.compile(rb"SSH-([\d.]+)"),
            sig_type="match",
            version_details=version,
        )
        return Probe(
            name="NULL",
            protocol="tcp",
            ports=[22],
            sslports=[],
            fallbacks=[],
            probe_string="",
            Signatures=[signature],
        )

    def test_hard_match_returns_service_immediately(self):
        probe = self._make_probe_with_signature()
        engine = ProbeEngine(
            port=22, protocol="tcp", host="127.0.0.1", probes_by_name={"NULL": probe}
        )
        fake_response = {"raw_bytes": b"SSH-2.0\r\n", "ssl_flag": False}
        with patch("nettacker.probing.engine.tcp_probe", return_value=fake_response):
            result = engine.probe_sequentially()
        assert result["service"] == "ssh"

    def test_no_response_returns_none(self):
        probe = self._make_probe_with_signature()
        engine = ProbeEngine(
            port=22, protocol="tcp", host="127.0.0.1", probes_by_name={"NULL": probe}
        )
        with patch("nettacker.probing.engine.tcp_probe", return_value=None):
            result = engine.probe_sequentially()
        assert result is None

    def test_udp_protocol_uses_udp_probe(self):
        probe = Probe(
            name="NULL",
            protocol="udp",
            ports=[53],
            sslports=[],
            fallbacks=[],
            probe_string="",
            Signatures=self._make_probe_with_signature().Signatures,
        )
        engine = ProbeEngine(
            port=53, protocol="udp", host="127.0.0.1", probes_by_name={"NULL": probe}
        )
        fake_response = {"raw_bytes": b"SSH-2.0\r\n", "ssl_flag": False}
        with patch("nettacker.probing.engine.udp_probe", return_value=fake_response) as mock_udp:
            result = engine.probe_sequentially()
        mock_udp.assert_called_once()
        assert result["service"] == "ssh"
