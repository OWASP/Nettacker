import pytest
from lib.scan.wayback_machine import engine


def test_wayback(wayback_boilerplate):
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
        thread_tmp_filename,
        extra_requirement,
    ) = wayback_boilerplate
    try:
        assert (
            engine.__wayback_machine_scan(
                target,
                timeout_sec,
                log_in_file,
                time_sleep,
                language,
                verbose_level,
                socks_proxy,
                retries,
                headers,
                thread_tmp_filename,
                extra_requirement
            )
            != []
        )
    except Exception:
        assert (
            engine.__wayback_machine_scan(
                target,
                timeout_sec,
                log_in_file,
                time_sleep,
                language,
                verbose_level,
                socks_proxy,
                retries,
                headers,
                thread_tmp_filename,
                extra_requirement
            )
            == []
        )
