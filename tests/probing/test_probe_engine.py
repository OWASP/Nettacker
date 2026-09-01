import re
from unittest.mock import patch

from nettacker.probing.engine import ProbeEngine, expand_template, interpret, printable
from nettacker.probing.loader import Probe, Signature, VersionDetails


def _regex_match(pattern, data):
    return re.search(pattern, data)


class TestInterpret:
    def test_big_endian(self):
        assert interpret(b"\x00\x01", ">") == 1

    def test_little_endian(self):
        assert interpret(b"\x01\x00", "<") == 1

    def test_accepts_string_input(self):
        assert interpret("\x00\x01", ">") == 1

    def test_truncates_to_eight_bytes(self):
        assert interpret(b"\xff" * 16, ">") == interpret(b"\xff" * 8, ">")


class TestPrintable:
    def test_strips_nulls_and_non_printables(self):
        assert printable(b"AB\x00\xffC") == "ABC"

    def test_accepts_str_input(self):
        assert printable("AB\x00C") == "ABC"


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

    def test_unmatched_optional_group_returns_empty_string_not_none(self):
        # group(2) exists (in range) but didn't participate in the match, so
        # re.Match.group() returns None. expand_place/$P/$I used to hand that
        # None straight back to re.sub, which requires a string and raised
        # TypeError - e.g. the bundled OpenFTPD signature's optional version
        # group ("^220 OpenFTPD server(\d[\w.]+)?\r\n") referenced as $1.
        match = _regex_match(rb"(\w+)(-\w+)?", b"foo")
        assert expand_template("$1/$2", match) == "foo/"
        assert expand_template("$P(2)", match) == ""
        assert expand_template("$I(2,>)", match) == ""


class TestProbeEngineFiltering:
    def _make_probe(self, name, protocol, ports=None, sslports=None):
        return Probe(
            name=name,
            protocol=protocol,
            ports=ports or [],
            sslports=sslports or [],
            fallbacks=[],
            probe_string="",
            signatures=[],
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


class TestProbeEngineExcludedPorts:
    """Raw-print listeners (TCP 9100-9107 in the bundled database) must never
    receive probe payloads, regardless of which module/port list selected them."""

    def _make_probe(self, name, protocol, ports=None, sslports=None):
        return Probe(
            name=name,
            protocol=protocol,
            ports=ports or [],
            sslports=sslports or [],
            fallbacks=[],
            probe_string="",
            signatures=[],
        )

    @patch(
        "nettacker.probing.engine.get_excluded_ports",
        return_value={"tcp": {9100}, "udp": set()},
    )
    def test_get_probes_for_port_returns_nothing_for_excluded_port(self, _mock_excluded):
        probes = {"HTTP": self._make_probe("HTTP", "tcp", ports=[9100])}
        engine = ProbeEngine(port=9100, protocol="tcp", host="127.0.0.1", probes_by_name=probes)
        assert engine.get_probes_for_port() == []

    @patch(
        "nettacker.probing.engine.get_excluded_ports",
        return_value={"tcp": {9100}, "udp": set()},
    )
    def test_get_probes_for_sslport_returns_nothing_for_excluded_port(self, _mock_excluded):
        probes = {"TLS": self._make_probe("TLS", "tcp", sslports=[9100])}
        engine = ProbeEngine(port=9100, protocol="tcp", host="127.0.0.1", probes_by_name=probes)
        assert engine.get_probes_for_sslport() == []

    @patch(
        "nettacker.probing.engine.get_excluded_ports",
        return_value={"tcp": {9100}, "udp": set()},
    )
    def test_exclusion_is_protocol_scoped(self, _mock_excluded):
        probes = {"DNS": self._make_probe("DNS", "udp", ports=[9100])}
        engine = ProbeEngine(port=9100, protocol="udp", host="127.0.0.1", probes_by_name=probes)
        assert [p.name for p in engine.get_probes_for_port()] == ["DNS"]


class TestProbeEngineWaitMs:
    def test_caps_probe_totalwaits_to_configured_timeout(self):
        probe = Probe(name="Slow", protocol="tcp", totalwaits=11000, signatures=[])
        engine = ProbeEngine(
            port=80, protocol="tcp", host="127.0.0.1", probes_by_name={}, timeout_ms=3000
        )
        assert engine._wait_ms(probe) == 3000

    def test_uses_probes_own_totalwaits_when_shorter_than_timeout(self):
        probe = Probe(name="Fast", protocol="tcp", totalwaits=1000, signatures=[])
        engine = ProbeEngine(
            port=80, protocol="tcp", host="127.0.0.1", probes_by_name={}, timeout_ms=3000
        )
        assert engine._wait_ms(probe) == 1000

    def test_uses_probes_own_totalwaits_when_no_timeout_configured(self):
        probe = Probe(name="Default", protocol="tcp", totalwaits=6000, signatures=[])
        engine = ProbeEngine(port=80, protocol="tcp", host="127.0.0.1", probes_by_name={})
        assert engine._wait_ms(probe) == 6000


class TestFallbackResolution:
    def test_fallback_is_scoped_to_the_probing_protocol(self):
        # The bundled database defines both a TCP and a UDP probe under some
        # shared names (RPCCheck, Help, Kerberos, OpenVPN, SIPOptions). A TCP
        # probe's fallback must resolve to the TCP probe of that name, never
        # the UDP one sharing it.
        version = VersionDetails(raw="", version_template="$1", product="TCPProduct")
        tcp_sig = Signature(
            service="tcp-svc", regex=re.compile(rb"X-(\d+)"), version_details=version
        )
        tcp_shared = Probe(name="Shared", protocol="tcp", signatures=[tcp_sig])
        udp_shared = Probe(name="Shared", protocol="udp", signatures=[])
        probes = {("tcp", "Shared"): tcp_shared, ("udp", "Shared"): udp_shared}

        probe = Probe(name="NULL", protocol="tcp", ports=[80], fallbacks=["Shared"])
        engine = ProbeEngine(port=80, protocol="tcp", host="127.0.0.1", probes_by_name=probes)
        fake_response = {"raw_bytes": b"X-7", "ssl_flag": False}
        with patch("nettacker.probing.engine.tcp_probe", return_value=fake_response):
            with patch.object(engine, "get_probes_for_port", return_value=[probe]):
                result = engine.probe_sequentially()
        assert result["service"] == "tcp-svc"

    def test_null_fallback_resolves_regardless_of_probing_protocol(self):
        # NULL just reads whatever banner is sent without a payload, so it's
        # usable as a fallback for both TCP and UDP probes.
        version = VersionDetails(raw="", version_template="$1", product="NullProduct")
        null_sig = Signature(
            service="banner", regex=re.compile(rb"Y-(\d+)"), version_details=version
        )
        null_probe = Probe(name="NULL", protocol="tcp", signatures=[null_sig])
        probes = {("tcp", "NULL"): null_probe}

        probe = Probe(name="DNS", protocol="udp", ports=[53], fallbacks=["NULL"])
        engine = ProbeEngine(port=53, protocol="udp", host="127.0.0.1", probes_by_name=probes)
        fake_response = {"raw_bytes": b"Y-9", "ssl_flag": False}
        with patch("nettacker.probing.engine.udp_probe", return_value=fake_response):
            with patch.object(engine, "get_probes_for_port", return_value=[probe]):
                result = engine.probe_sequentially()
        assert result["service"] == "banner"


class TestMatchResponse:
    def _make_signature(self, sig_type="match", service="ssh", regex=b"SSH-([\\d.]+)"):
        version = VersionDetails(
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
        result = engine.match_response(None, self._make_signature())
        assert result["status"] is False

    def test_matching_response_extracts_version(self):
        engine = ProbeEngine(port=22, protocol="tcp", host="127.0.0.1", probes_by_name={})
        signature = self._make_signature()
        result = engine.match_response(b"SSH-2.0\r\n", signature)
        assert result["status"] is True
        assert result["result"].version_template == "2.0"
        assert result["result"].product == "OpenSSH"

    def test_non_matching_response(self):
        engine = ProbeEngine(port=22, protocol="tcp", host="127.0.0.1", probes_by_name={})
        signature = self._make_signature()
        result = engine.match_response(b"HTTP/1.1 200 OK\r\n", signature)
        assert result["status"] is False


class TestProbeSequentially:
    def _make_probe_with_signature(self):
        version = VersionDetails(raw="", version_template="$1", product="OpenSSH")
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
            signatures=[signature],
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
            signatures=self._make_probe_with_signature().signatures,
        )
        engine = ProbeEngine(
            port=53, protocol="udp", host="127.0.0.1", probes_by_name={"NULL": probe}
        )
        fake_response = {"raw_bytes": b"SSH-2.0\r\n", "ssl_flag": False}
        with patch("nettacker.probing.engine.udp_probe", return_value=fake_response) as mock_udp:
            result = engine.probe_sequentially()
        mock_udp.assert_called_once()
        assert result["service"] == "ssh"
