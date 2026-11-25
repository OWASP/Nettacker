import pytest

import nettacker.probing.loader as loader_module
from nettacker.probing.loader import build_probes_from_yaml, load_probes_from_yaml


@pytest.fixture(autouse=True)
def reset_probes_cache():
    """Each test gets a clean module-level cache so tests don't leak state."""

    def _reset():
        loader_module._PROBES_CACHE = None
        loader_module._probes_by_name = {}
        loader_module._excluded_ports = {"tcp": set(), "udp": set()}

    _reset()
    yield
    _reset()


PROBE_YAML = """
Excluded ports:
  - {}
probes:
  - name: "NULL"
    protocol: tcp
    totalwaits: 6000
    tcpwrappedms: 3000
    rarity: 1
    ports: [22]
    sslports: []
    fallbacks: []
    probe_string: ""
    no_payload: false
    signatures:
      - type: match
        service: ssh
        regex: "SSH-([\\\\d.]+)"
        Ignore_case: false
        New_line_specifier: false
        version:
          version_template: "$1"
          product: "OpenSSH"
  - name: BROKEN
    protocol: tcp
    ports: [23]
    signatures:
      - type: match
        service: broken
        regex: "("
  - name: DNS_UDP
    protocol: udp
    ports: [53]
    signatures: []
"""


class TestLoadProbesFromYaml:
    def test_loads_probes_from_configured_path(self, tmp_path, monkeypatch):
        probes_file = tmp_path / "probes.yaml"
        probes_file.write_text(PROBE_YAML)
        monkeypatch.setattr(loader_module.Config.path, "probes_yaml_file", probes_file)

        probes = load_probes_from_yaml()

        # Keyed by (protocol, name): a name-only key can't hold both a TCP and a
        # UDP probe sharing the same name without one silently overwriting the other.
        assert ("tcp", "NULL") in probes
        assert probes[("tcp", "NULL")].protocol == "tcp"
        assert probes[("tcp", "NULL")].ports == [22]
        assert len(probes[("tcp", "NULL")].signatures) == 1

    def test_null_fallback_is_always_appended(self, tmp_path, monkeypatch):
        probes_file = tmp_path / "probes.yaml"
        probes_file.write_text(PROBE_YAML)
        monkeypatch.setattr(loader_module.Config.path, "probes_yaml_file", probes_file)

        probes = load_probes_from_yaml()

        # BROKEN (tcp) implicitly falls back to NULL; NULL itself must not (it
        # would otherwise evaluate its own signatures a second time as its own
        # fallback). NULL is TCP-only, so a UDP probe must not get it either.
        assert "NULL" in probes[("tcp", "BROKEN")].fallbacks
        assert "NULL" not in probes[("tcp", "NULL")].fallbacks
        assert "NULL" not in probes[("udp", "DNS_UDP")].fallbacks

    def test_broken_regex_signature_is_skipped_not_fatal(self, tmp_path, monkeypatch):
        probes_file = tmp_path / "probes.yaml"
        probes_file.write_text(PROBE_YAML)
        monkeypatch.setattr(loader_module.Config.path, "probes_yaml_file", probes_file)

        probes = load_probes_from_yaml()

        assert ("tcp", "BROKEN") in probes
        assert probes[("tcp", "BROKEN")].signatures == []

    def test_compiled_signature_regex_is_usable(self, tmp_path, monkeypatch):
        probes_file = tmp_path / "probes.yaml"
        probes_file.write_text(PROBE_YAML)
        monkeypatch.setattr(loader_module.Config.path, "probes_yaml_file", probes_file)

        probes = load_probes_from_yaml()
        sig = probes[("tcp", "NULL")].signatures[0]
        assert sig.regex.search(b"SSH-2.0\r\n")

    def test_second_call_uses_cache(self, tmp_path, monkeypatch):
        probes_file = tmp_path / "probes.yaml"
        probes_file.write_text(PROBE_YAML)
        monkeypatch.setattr(loader_module.Config.path, "probes_yaml_file", probes_file)

        first = load_probes_from_yaml()
        probes_file.write_text("probes: []\n")  # change on disk, should not matter now
        second = load_probes_from_yaml()

        assert first is second

    def test_missing_probes_key_raises_value_error(self, tmp_path, monkeypatch):
        probes_file = tmp_path / "probes.yaml"
        probes_file.write_text("not_probes: []\n")
        monkeypatch.setattr(loader_module.Config.path, "probes_yaml_file", probes_file)

        with pytest.raises(ValueError):
            load_probes_from_yaml()

    def test_empty_file_raises_value_error(self, tmp_path, monkeypatch):
        probes_file = tmp_path / "probes.yaml"
        probes_file.write_text("")
        monkeypatch.setattr(loader_module.Config.path, "probes_yaml_file", probes_file)

        with pytest.raises(ValueError):
            load_probes_from_yaml()


class TestBuildProbesFromYaml:
    def test_loads_lazily_when_cache_empty(self, tmp_path, monkeypatch):
        probes_file = tmp_path / "probes.yaml"
        probes_file.write_text(PROBE_YAML)
        monkeypatch.setattr(loader_module.Config.path, "probes_yaml_file", probes_file)

        probes = build_probes_from_yaml()

        assert ("tcp", "NULL") in probes

    def test_returns_same_dict_as_module_cache(self, tmp_path, monkeypatch):
        probes_file = tmp_path / "probes.yaml"
        probes_file.write_text(PROBE_YAML)
        monkeypatch.setattr(loader_module.Config.path, "probes_yaml_file", probes_file)

        probes = build_probes_from_yaml()
        assert probes is loader_module._probes_by_name


class TestRealPackagedProbesFile:
    def test_real_probes_yaml_loads_and_has_entries(self):
        probes = load_probes_from_yaml()
        assert len(probes) > 0
        assert ("tcp", "NULL") in probes
