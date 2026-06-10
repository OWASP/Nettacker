"""
Comprehensive tests for TemplateLoader including parse, format, and load methods.
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open
import yaml

from nettacker.core.template import TemplateLoader


class TestTemplateLoaderInit:
    """Test TemplateLoader initialization."""
    
    def test_initialization_with_name_only(self):
        """Test initialization with just a name."""
        loader = TemplateLoader("http_scan_scan")
        assert loader.name == "http_scan_scan"
        assert loader.inputs == {}
    
    def test_initialization_with_name_and_inputs(self):
        """Test initialization with name and inputs."""
        inputs = {"port": "80", "timeout": "10"}
        loader = TemplateLoader("http_scan_scan", inputs=inputs)
        assert loader.name == "http_scan_scan"
        assert loader.inputs == inputs
    
    def test_initialization_with_none_inputs(self):
        """Test that None inputs are converted to empty dict."""
        loader = TemplateLoader("http_scan_scan", inputs=None)
        assert loader.inputs == {}


class TestTemplateLoaderParse:
    """Test static parse method."""
    
    def test_parse_dict_with_matching_input(self):
        """Test parse replaces dict values with matching inputs."""
        content = {"host": "{host}", "port": "80"}
        inputs = {"host": "example.com"}
        result = TemplateLoader.parse(content, inputs)
        assert result["host"] == "example.com"
        assert result["port"] == "80"
    
    def test_parse_dict_with_nonmatching_input(self):
        """Test parse ignores non-matching dict keys."""
        content = {"host": "default.com", "port": "80"}
        inputs = {"timeout": "10"}
        result = TemplateLoader.parse(content, inputs)
        assert result["host"] == "default.com"
        assert result["port"] == "80"
    
    def test_parse_nested_dict(self):
        """Test parse handles nested dictionaries."""
        content = {"level1": {"host": "{host}", "port": 80}}
        inputs = {"host": "example.com"}
        result = TemplateLoader.parse(content, inputs)
        assert result["level1"]["host"] == "example.com"
    
    def test_parse_list_elements(self):
        """Test parse handles list elements."""
        content = [{"host": "{host}"}, {"port": 80}]
        inputs = {"host": "example.com"}
        result = TemplateLoader.parse(content, inputs)
        assert result[0]["host"] == "example.com"
        assert result[1]["port"] == 80
    
    def test_parse_nested_list_in_dict(self):
        """Test parse handles lists within dicts."""
        content = {"servers": [{"host": "primary.com"}, {"host": "backup.com"}]}
        inputs = {}
        result = TemplateLoader.parse(content, inputs)
        assert result["servers"][0]["host"] == "primary.com"
        assert result["servers"][1]["host"] == "backup.com"
    
    def test_parse_with_truthy_input_value(self):
        """Test parse uses input value when present and truthy."""
        content = {"enabled": False}
        inputs = {"enabled": True}
        result = TemplateLoader.parse(content, inputs)
        assert result["enabled"] is True
    
    def test_parse_with_falsy_input_value(self):
        """Test parse skips empty/falsy input values."""
        content = {"enabled": True}
        inputs = {"enabled": ""}
        result = TemplateLoader.parse(content, inputs)
        # Empty string is falsy, so original value is kept
        assert result["enabled"] is True
    
    def test_parse_preserves_types_in_nested_dict(self):
        """Test parse handles nested structures with various types."""
        content = {
            "timeout": 30,
            "nested": {
                "delay": 0.5,
                "data": b"binary"
            }
        }
        inputs = {}
        result = TemplateLoader.parse(content, inputs)
        assert result["timeout"] == 30
        assert result["nested"]["delay"] == 0.5
        assert result["nested"]["data"] == b"binary"
    
    def test_parse_empty_dict(self):
        """Test parse with empty dict."""
        content = {}
        inputs = {"host": "example.com"}
        result = TemplateLoader.parse(content, inputs)
        assert result == {}
    
    def test_parse_empty_list(self):
        """Test parse with empty list."""
        content = []
        inputs = {"host": "example.com"}
        result = TemplateLoader.parse(content, inputs)
        assert result == []


class TestTemplateLoaderOpen:
    """Test open method for reading YAML files."""
    
    def test_open_valid_template(self, tmp_path):
        """Test opening a valid template file."""
        mock_yaml_content = "target: '{target}'\nport: 80\n"
        expected_path = tmp_path / "scan" / "http_scan.yaml"

        with patch("nettacker.core.template.Config.path.modules_dir", tmp_path):
            with patch("builtins.open", mock_open(read_data=mock_yaml_content)) as mocked_open:
                loader = TemplateLoader("http_scan_scan")
                result = loader.open()
                assert isinstance(result, str)
                mocked_open.assert_called_once_with(expected_path)
    
    def test_open_extracts_module_name_correctly(self, tmp_path):
        """Test that open correctly parses module name."""
        mock_yaml_content = "test: data\n"
        expected_path = tmp_path / "scan" / "port_scan.yaml"

        with patch("nettacker.core.template.Config.path.modules_dir", tmp_path):
            with patch("builtins.open", mock_open(read_data=mock_yaml_content)) as mocked_open:
                loader = TemplateLoader("port_scan_scan")
                loader.open()
                assert loader.name == "port_scan_scan"
                mocked_open.assert_called_once_with(expected_path)


class TestTemplateLoaderFormat:
    """Test format method."""
    
    def test_format_with_inputs(self):
        """Test format substitutes inputs into YAML string."""
        mock_yaml = "target: '{target}'\nport: {port}\n"
        
        with patch.object(TemplateLoader, "open", return_value=mock_yaml):
            loader = TemplateLoader("http_scan_scan", inputs={"target": "example.com", "port": "80"})
            result = loader.format()
            assert "example.com" in result
            assert "80" in result
    
    def test_format_without_inputs(self):
        """Test format on YAML without placeholders."""
        mock_yaml = "target: localhost\nport: 80\n"
        
        with patch.object(TemplateLoader, "open", return_value=mock_yaml):
            loader = TemplateLoader("http_scan_scan")
            result = loader.format()
            assert result == mock_yaml
    
    def test_format_with_all_inputs_provided(self):
        """Test format with all required inputs provided."""
        mock_yaml = "target: '{target}'\nport: '{port}'\n"
        
        with patch.object(TemplateLoader, "open", return_value=mock_yaml):
            loader = TemplateLoader("http_scan_scan", inputs={"target": "example.com", "port": "80"})
            result = loader.format()
            assert "example.com" in result
            assert "80" in result


class TestTemplateLoaderLoad:
    """Test load method which combines format and parse."""
    
    def test_load_yaml_with_inputs(self):
        """Test load properly parses YAML and applies inputs."""
        mock_yaml = "requests:\n  - host: '{host}'\n    port: 80\n"
        formatted_yaml = "requests:\n  - host: 'example.com'\n    port: 80\n"
        
        with patch.object(TemplateLoader, "open", return_value=mock_yaml):
            loader = TemplateLoader("http_scan_scan", inputs={"host": "example.com"})
            result = loader.load()
            
            # Result should be a parsed YAML dict
            assert isinstance(result, dict)
            assert "requests" in result
    
    def test_load_returns_parsed_dict(self):
        """Test load returns parsed YAML as dict."""
        mock_yaml = "key: value\nnumber: 42\n"
        
        with patch.object(TemplateLoader, "open", return_value=mock_yaml):
            loader = TemplateLoader("scan_test")
            result = loader.load()
            
            assert isinstance(result, dict)
            assert result.get("key") == "value"
            assert result.get("number") == 42
    
    def test_load_with_nested_yaml(self):
        """Test load with complex nested YAML structure."""
        mock_yaml = """
steps:
  - name: scan
    params:
      host: '{target}'
      port: 80
"""
        
        with patch.object(TemplateLoader, "open", return_value=mock_yaml):
            loader = TemplateLoader("port_scan_scan", inputs={"target": "example.com"})
            result = loader.load()
            
            assert isinstance(result, dict)
            assert "steps" in result
            assert isinstance(result["steps"], list)
    
    def test_load_with_list_yaml(self):
        """Test load when YAML root is a list."""
        mock_yaml = "- host: localhost\n  port: 80\n- host: example.com\n  port: 443\n"
        
        with patch.object(TemplateLoader, "open", return_value=mock_yaml):
            loader = TemplateLoader("scan_test")
            result = loader.load()
            
            assert isinstance(result, list)
            assert len(result) == 2


class TestTemplateLoaderIntegration:
    """Integration tests combining multiple methods."""
    
    def test_full_workflow(self):
        """Test complete template loading workflow."""
        mock_yaml = """
module: scan
target: '{host}'
ports:
  - 80
  - 443
"""
        
        with patch.object(TemplateLoader, "open", return_value=mock_yaml):
            loader = TemplateLoader("http_scan_scan", inputs={"host": "target.com"})
            
            # Test each method in sequence
            formatted = loader.format()
            assert "target.com" in formatted
            
            loaded = loader.load()
            assert isinstance(loaded, dict)
            assert loaded["module"] == "scan"
            assert loaded["target"] == "target.com"
            assert 80 in loaded["ports"]
    
    def test_loader_with_multiple_templates(self):
        """Test creating multiple loaders with different templates."""
        mock_yaml1 = "type: scan\ntarget: '{host}'\n"
        mock_yaml2 = "type: brute\nuser: '{user}'\n"
        
        with patch.object(TemplateLoader, "open") as mock_open_method:
            mock_open_method.side_effect = [mock_yaml1, mock_yaml2]
            
            loader1 = TemplateLoader("port_scan_scan", {"host": "example.com"})
            loader2 = TemplateLoader("ssh_brute_brute", {"user": "admin"})
            
            result1 = loader1.load()
            result2 = loader2.load()
            
            assert result1["target"] == "example.com"
            assert result2["user"] == "admin"
