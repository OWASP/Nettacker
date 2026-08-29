import re

import pytest
import yaml

import nettacker.probing.loader as loader_module
from nettacker.probing.loader import build_probes_from_yaml, load_probes_from_yaml


@pytest.fixture(autouse=True)
def reset_probes_cache():
    """Each test gets a clean module-level cache so tests don't leak state."""
    loader_module._PROBES_CACHE = None
    loader_module._probes_by_name = {}
    yield
    loader_module._PROBES_CACHE = None
    loader_module._probes_by_name = {}


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
"""


class TestLoadProbesFromYaml:
    def test_loads_probes_from_configured_path(self, tmp_path, monkeypatch):
        probes_file = tmp_path / "probes.yaml"
        probes_file.write_text(PROBE_YAML)
        monkeypatch.setattr(loader_module.Config.path, "probes_yaml_file", probes_file)

        probes = load_probes_from_yaml()

        assert "NULL" in probes
        assert probes["NULL"].protocol == "tcp"
        assert probes["NULL"].ports == [22]
        assert len(probes["NULL"].Signatures) == 1

    def test_null_fallback_is_always_appended(self, tmp_path, monkeypatch):
        probes_file = tmp_path / "probes.yaml"
        probes_file.write_text(PROBE_YAML)
        monkeypatch.setattr(loader_module.Config.path, "probes_yaml_file", probes_file)

        probes = load_probes_from_yaml()

        assert "NULL" in probes["NULL"].fallbacks

    def test_broken_regex_signature_is_skipped_not_fatal(self, tmp_path, monkeypatch):
        probes_file = tmp_path / "probes.yaml"
        probes_file.write_text(PROBE_YAML)
        monkeypatch.setattr(loader_module.Config.path, "probes_yaml_file", probes_file)

        probes = load_probes_from_yaml()

        assert "BROKEN" in probes
        assert probes["BROKEN"].Signatures == []

    def test_compiled_signature_regex_is_usable(self, tmp_path, monkeypatch):
        probes_file = tmp_path / "probes.yaml"
        probes_file.write_text(PROBE_YAML)
        monkeypatch.setattr(loader_module.Config.path, "probes_yaml_file", probes_file)

        probes = load_probes_from_yaml()
        sig = probes["NULL"].Signatures[0]
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

        assert "NULL" in probes

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
        assert "NULL" in probes
