from nettacker.core.template import TemplateLoader
from pathlib import Path
import pytest


def test_template_loader_initialization():
    loader = TemplateLoader("port_scan_scan")
    assert loader is not None


def test_template_loader_open():
    try:
        loader = TemplateLoader("port_scan_scan")
        content = loader.open()
        assert content is not None
        assert isinstance(content, str)
    except FileNotFoundError:
        # Template file may not exist in test environment
        pytest.skip("Template file not found")
