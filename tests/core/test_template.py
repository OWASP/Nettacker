import re
from unittest.mock import patch

import pytest

from nettacker.core.template import TemplateLoader


@pytest.fixture
def loader():
    return TemplateLoader("dummy_vuln", {"target": "example.com"})


def test_rand_str_is_replaced_with_requested_length(loader):
    result = loader._apply_dynamic_placeholders("path: /{rand_str(10)}")
    match = re.fullmatch(r"path: /([a-z]+)", result)
    assert match
    assert len(match.group(1)) == 10


def test_rand_str_length_is_capped_at_256(loader):
    result = loader._apply_dynamic_placeholders("{rand_str(1000)}")
    assert len(result) == 256
    assert result.isalpha() and result.islower()


def test_multiple_rand_str_placeholders_are_each_replaced(loader):
    result = loader._apply_dynamic_placeholders("{rand_str(5)}-{rand_str(8)}")
    first, second = result.split("-")
    assert len(first) == 5
    assert len(second) == 8
    assert "rand_str" not in result


def test_content_without_placeholders_is_unchanged(loader):
    content = "url: http://{target}/index.php"
    assert loader._apply_dynamic_placeholders(content) == content


def test_format_expands_rand_str_and_regular_placeholders(loader):
    content = "url: http://{target}/{rand_str(12)}"
    with patch.object(TemplateLoader, "open", return_value=content):
        result = loader.format()
    match = re.fullmatch(r"url: http://example\.com/([a-z]+)", result)
    assert match
    assert len(match.group(1)) == 12
