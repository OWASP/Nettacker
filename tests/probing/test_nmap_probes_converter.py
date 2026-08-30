import yaml

from nettacker.probing.nmap_probes_converter import (
    parse_excluded,
    parse_ports,
    parse_probe_file,
    parse_ssl_ports,
    write_yaml,
)

SAMPLE_PROBES_TXT = """\
Exclude T:9100-9101,U:69
Probe TCP NULL q||
rarity 1
ports 21,80,8000-8001
sslports 443
fallback GenericLines
match ftp m/^220.*FTP/i p/FooFTP/ v/1.2/
softmatch generic m/^HELLO/s
Probe UDP DNSVersionBindReqTCP q|test|
rarity 3
ports 53
"""


class TestParseExcluded:
    def test_empty_line(self):
        assert parse_excluded("") == []

    def test_splits_by_protocol(self):
        result = parse_excluded("Exclude T:9100-9101,U:69")
        assert result == {"TCP": "9100-9101", "UDP": "69", "Universal": ""}

    def test_universal_port_with_no_protocol_prefix(self):
        result = parse_excluded("Exclude 23,53")
        assert result == {"TCP": "", "UDP": "", "Universal": "23,53"}


class TestParsePorts:
    def test_empty_line(self):
        assert parse_ports("") == []

    def test_single_ports(self):
        assert parse_ports("ports 21,80") == [21, 80]

    def test_port_ranges_are_expanded(self):
        assert parse_ports("ports 21-23") == [21, 22, 23]

    def test_mixed_single_and_range(self):
        assert parse_ports("ports 21,8000-8002") == [21, 8000, 8001, 8002]


class TestParseSslPorts:
    def test_empty_line(self):
        assert parse_ssl_ports("") == []

    def test_single_port(self):
        assert parse_ssl_ports("sslports 443") == [443]


class TestParseProbeFile:
    def test_parses_excluded_ports(self, tmp_path):
        probe_file = tmp_path / "nmap-service-probes.txt"
        probe_file.write_text(SAMPLE_PROBES_TXT)

        _, excluded_ports = parse_probe_file(str(probe_file))
        assert excluded_ports == {"TCP": "9100-9101", "UDP": "69", "Universal": ""}

    def test_parses_two_probes(self, tmp_path):
        probe_file = tmp_path / "nmap-service-probes.txt"
        probe_file.write_text(SAMPLE_PROBES_TXT)

        probes, _ = parse_probe_file(str(probe_file))
        names = [p["name"] for p in probes]
        assert names == ["NULL", "DNSVersionBindReqTCP"]

    def test_probe_fields(self, tmp_path):
        probe_file = tmp_path / "nmap-service-probes.txt"
        probe_file.write_text(SAMPLE_PROBES_TXT)

        probes, _ = parse_probe_file(str(probe_file))
        null_probe = probes[0]
        assert null_probe["protocol"] == "TCP"
        assert null_probe["rarity"] == 1
        assert null_probe["ports"] == [21, 80, 8000, 8001]
        assert null_probe["sslports"] == [443]
        assert null_probe["fallbacks"] == ["GenericLines"]
        assert null_probe["probe_string"] == ""

    def test_match_signature_parsed(self, tmp_path):
        probe_file = tmp_path / "nmap-service-probes.txt"
        probe_file.write_text(SAMPLE_PROBES_TXT)

        probes, _ = parse_probe_file(str(probe_file))
        signatures = probes[0]["signatures"]
        match_sig = signatures[0]
        assert match_sig["type"] == "match"
        assert match_sig["service"] == "ftp"
        assert match_sig["regex"] == "^220.*FTP"
        assert match_sig["Ignore_case"] is True
        assert match_sig["version"]["product"] == "FooFTP"
        assert match_sig["version"]["version_template"] == "1.2"

    def test_softmatch_signature_parsed(self, tmp_path):
        probe_file = tmp_path / "nmap-service-probes.txt"
        probe_file.write_text(SAMPLE_PROBES_TXT)

        probes, _ = parse_probe_file(str(probe_file))
        signatures = probes[0]["signatures"]
        soft_sig = signatures[1]
        assert soft_sig["type"] == "softmatch"
        assert soft_sig["service"] == "generic"
        assert soft_sig["regex"] == "^HELLO"
        assert soft_sig["New_line_specifier"] is True

    def test_second_probe_has_payload(self, tmp_path):
        probe_file = tmp_path / "nmap-service-probes.txt"
        probe_file.write_text(SAMPLE_PROBES_TXT)

        probes, _ = parse_probe_file(str(probe_file))
        udp_probe = probes[1]
        assert udp_probe["protocol"] == "UDP"
        assert udp_probe["probe_string"] == "test"
        assert udp_probe["ports"] == [53]

    def test_comments_and_blank_lines_are_skipped(self, tmp_path):
        probe_file = tmp_path / "nmap-service-probes.txt"
        probe_file.write_text("# a comment\n\n" + SAMPLE_PROBES_TXT)

        probes, _ = parse_probe_file(str(probe_file))
        assert len(probes) == 2


class TestWriteYaml:
    def test_round_trips_through_yaml(self, tmp_path):
        probe_file = tmp_path / "nmap-service-probes.txt"
        probe_file.write_text(SAMPLE_PROBES_TXT)
        out_file = tmp_path / "probes.yaml"

        probes, excluded_ports = parse_probe_file(str(probe_file))
        write_yaml(probes, excluded_ports, str(out_file))

        with open(out_file) as f:
            data = yaml.safe_load(f)

        assert "probes" in data
        assert len(data["probes"]) == 2
        assert data["probes"][0]["name"] == "NULL"
        assert "Excluded ports" in data
