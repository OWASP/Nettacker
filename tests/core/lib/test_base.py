from unittest.mock import patch

from nettacker.core.lib.base import BaseEngine, BaseLibrary


class ConcreteEngine(BaseEngine):
    """Concrete subclass for testing abstract BaseEngine methods."""

    library = BaseLibrary


class TestBaseLibrary:
    def test_base_library_client_is_none(self):
        assert BaseLibrary.client is None

    def test_base_library_brute_force_returns_none(self):
        library = BaseLibrary()
        assert library.brute_force() is None


class TestBaseEngineFilterLargeContent:
    def setup_method(self):
        self.engine = ConcreteEngine()

    def test_short_content_returned_unchanged(self):
        content = "short string"
        assert self.engine.filter_large_content(content) == content

    def test_exactly_150_chars_returned_unchanged(self):
        content = "x" * 150
        assert self.engine.filter_large_content(content) == content

    @patch("nettacker.core.lib.base._", return_value=" ... [filtered]")
    def test_long_content_truncated_at_word_boundary(self, mock_messages):
        content = "a" * 155 + " " + "b" * 50
        result = self.engine.filter_large_content(content)
        assert result.endswith(" ... [filtered]")
        assert len(result) < len(content)

    @patch("nettacker.core.lib.base._", return_value=" ... [filtered]")
    def test_long_content_with_space_after_filter_rate(self, mock_messages):
        content = "a" * 155 + " rest of content"
        result = self.engine.filter_large_content(content)
        assert result.endswith(" ... [filtered]")

    def test_long_content_no_space_returns_full(self):
        content = "a" * 300
        result = self.engine.filter_large_content(content)
        assert result == content

    def test_custom_filter_rate(self):
        content = "a" * 50
        assert self.engine.filter_large_content(content, filter_rate=50) == content

    @patch("nettacker.core.lib.base._", return_value=" ... [filtered]")
    def test_custom_filter_rate_truncates(self, mock_messages):
        content = "a" * 10 + " " + "b" * 50
        result = self.engine.filter_large_content(content, filter_rate=10)
        assert result.endswith(" ... [filtered]")
