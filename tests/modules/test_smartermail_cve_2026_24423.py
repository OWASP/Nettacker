"""Tests for smartermail_cve_2026_24423 vulnerability module."""


import pytest
import yaml

from nettacker.config import Config


class TestSmarterMailCVE202624423:
    """Test suite for CVE-2026-24423 SmarterMail module."""

    @pytest.fixture
    def module_path(self):
        """Return the path to the module YAML file."""
        return Config.path.modules_dir / "vuln" / "smartermail_cve_2026_24423.yaml"

    @pytest.fixture
    def module_content(self, module_path):
        """Load and parse the module YAML content."""
        with open(module_path) as f:
            return yaml.safe_load(f)

    def test_module_file_exists(self, module_path):
        """Test that the module file exists."""
        assert module_path.exists(), f"Module file not found: {module_path}"

    def test_module_has_required_info_fields(self, module_content):
        """Test that the module has all required info fields."""
        info = module_content.get("info", {})
        required_fields = ["name", "author", "severity", "description", "reference", "profiles"]
        for field in required_fields:
            assert field in info, f"Missing required info field: {field}"

    def test_module_name_follows_convention(self, module_content):
        """Test that module name follows the naming convention."""
        name = module_content["info"]["name"]
        assert name.endswith("_vuln"), f"Module name should end with '_vuln': {name}"
        assert "cve_2026_24423" in name, f"Module name should contain CVE ID: {name}"

    def test_module_severity_is_valid(self, module_content):
        """Test that severity is a valid CVSS score."""
        severity = module_content["info"]["severity"]
        assert isinstance(severity, (int, float)), f"Severity should be numeric: {severity}"
        assert 0 <= severity <= 10, f"Severity should be between 0 and 10: {severity}"

    def test_module_has_cisa_kev_profile(self, module_content):
        """Test that module has cisa_kev profile tag."""
        profiles = module_content["info"]["profiles"]
        assert "cisa_kev" in profiles, "Module should have 'cisa_kev' profile"

    def test_module_has_required_profiles(self, module_content):
        """Test that module has all required profile tags."""
        profiles = module_content["info"]["profiles"]
        required_profiles = ["vuln", "http", "cve"]
        for profile in required_profiles:
            assert profile in profiles, f"Missing required profile: {profile}"

    def test_module_references_are_valid_urls(self, module_content):
        """Test that all references are valid URLs."""
        references = module_content["info"]["reference"]
        assert isinstance(references, list), "References should be a list"
        assert len(references) > 0, "Module should have at least one reference"
        for ref in references:
            assert ref.startswith("http"), f"Reference should be a URL: {ref}"

    def test_module_has_payloads(self, module_content):
        """Test that module has at least one payload."""
        payloads = module_content.get("payloads", [])
        assert len(payloads) > 0, "Module should have at least one payload"

    def test_payload_uses_http_library(self, module_content):
        """Test that payload uses the http library."""
        payload = module_content["payloads"][0]
        assert payload.get("library") == "http", "Payload should use 'http' library"

    def test_payload_has_steps(self, module_content):
        """Test that payload has at least one step."""
        payload = module_content["payloads"][0]
        steps = payload.get("steps", [])
        assert len(steps) > 0, "Payload should have at least one step"

    def test_step_has_required_fields(self, module_content):
        """Test that step has required HTTP fields."""
        step = module_content["payloads"][0]["steps"][0]
        required_fields = ["method", "url", "response"]
        for field in required_fields:
            assert field in step, f"Step missing required field: {field}"

    def test_step_response_has_conditions(self, module_content):
        """Test that step response has conditions."""
        step = module_content["payloads"][0]["steps"][0]
        response = step.get("response", {})
        assert "condition_type" in response, "Response should have condition_type"
        assert "conditions" in response, "Response should have conditions"

    def test_fuzzer_has_smartermail_paths(self, module_content):
        """Test that fuzzer includes SmarterMail-specific endpoint."""
        # Step 1 is the connect-to-hub endpoint (Step 0 is licensing/about for version detection)
        step = module_content["payloads"][0]["steps"][1]
        url_config = step.get("url", {})
        fuzzer = url_config.get("nettacker_fuzzer", {})
        input_format = fuzzer.get("input_format", "")
        # Check that the endpoint contains the vulnerable API path
        assert "hub" in input_format.lower(), "Should include hub endpoint path"
        assert "connect" in input_format.lower(), "Should include connect in endpoint"

