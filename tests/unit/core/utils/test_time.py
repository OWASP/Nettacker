import datetime

from nettacker.core.utils.time import now


def test_time_now_default_format():
    result = now()
    parsed = datetime.datetime.strptime(result, "%Y-%m-%d %H:%M:%S")
    assert isinstance(parsed, datetime.datetime)


def test_time_now_custom_format():
    result = now(format="%Y-%m-%d")
    parsed = datetime.datetime.strptime(result, "%Y-%m-%d")
    assert isinstance(parsed, datetime.datetime)
