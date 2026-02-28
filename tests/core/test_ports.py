import pytest
from nettacker.core.utils.ports import parse_port_expression

def test_single_port():
    assert parse_port_expression("80") == [80]

def test_multiple_ports():
    assert parse_port_expression("80,443") == [80,443]

def test_port_range():
    assert parse_port_expression("20-22") == [20,21,22]

def test_mixed_expression():
    assert parse_port_expression("20-22,80") == [20,21,22,80]

def test_invalid_range():
    with pytest.raises(ValueError):
        parse_port_expression("80-70")

def test_out_of_range_port():
    with pytest.raises(ValueError):
        parse_port_expression("99999")

def test_invalid_value():
    with pytest.raises(ValueError):
        parse_port_expression("abc")

