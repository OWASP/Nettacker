import pytest
from lib.scan.shodan import engine
import shodan
from pytest import mark

VALID_API_KEY = "3pJIWkJ8O5sUOA64hxmO3bpG2V8BYVQN"


def test_check_api_key_is_valid(apikeys):
    (
        target,
        timeout_sec,
        log_in_file,
        time_sleep,
        language,
        verbose_level,
        socks_proxy,
        retries,
        headers,
        shodan_api_key,
    ) = apikeys
    if shodan_api_key != VALID_API_KEY:
        assert (
            engine.__shodan_scan(
                target,
                timeout_sec,
                log_in_file,
                time_sleep,
                language,
                verbose_level,
                socks_proxy,
                retries,
                headers,
                shodan_api_key,
            )
            == []
        )
    else:
        if (
            len(
                engine.__shodan_scan(
                    target,
                    timeout_sec,
                    log_in_file,
                    time_sleep,
                    language,
                    verbose_level,
                    socks_proxy,
                    retries,
                    headers,
                    shodan_api_key,
                )
            )
            >= 0
        ):
            assert True
        else:
            assert False


def test_inet_working_properly(shodan_inet):
    (
        target,
        timeout_sec,
        log_in_file,
        time_sleep,
        language,
        verbose_level,
        socks_proxy,
        retries,
        headers,
        shodan_api_key,
    ) = shodan_inet
    if (
        len(
            engine.__shodan_scan(
                target,
                timeout_sec,
                log_in_file,
                time_sleep,
                language,
                verbose_level,
                socks_proxy,
                retries,
                headers,
                shodan_api_key,
            )
        )
        >= 0
    ):
        assert True
    else:
        assert False
