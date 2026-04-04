import sys

from nettacker.core.utils.common import (
    select_maximum_cpu_core,
    now,
    find_args_value,
    get_http_header_key,
    get_http_header_value,
    string_to_bytes,
)


def test_select_maximum_cpu_core_modes():
    assert select_maximum_cpu_core("low") >= 1
    assert select_maximum_cpu_core("normal") >= 1
    assert select_maximum_cpu_core("high") >= 1
    assert select_maximum_cpu_core("maximum") >= 1
    assert select_maximum_cpu_core("invalid") == 1


def test_now_format():
    result = now()
    assert len(result) == 19  # "%Y-%m-%d %H:%M:%S" format
    assert result.count("-") == 2
    assert result.count(":") == 2


def test_find_args_value_exists(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["prog", "-t", "example.com"])
    result = find_args_value("-t")
    assert result == "example.com"


def test_find_args_value_missing(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["prog"])
    result = find_args_value("-x")
    assert result is None


def test_get_http_header_key():
    assert get_http_header_key("Authorization: Bearer token") == "Authorization"
    assert get_http_header_key("X-Custom-Header: value") == "X-Custom-Header"


def test_get_http_header_value():
    assert get_http_header_value("Authorization: Bearer token") == "Bearer token"
    assert get_http_header_value("X-Custom: ") is None
    assert get_http_header_value("no-value") is None


def test_string_to_bytes():
    result = string_to_bytes("hello")
    assert result == b"hello"
    assert isinstance(result, bytes)
