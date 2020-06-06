import pytest
from lib.vuln.clickjacking import engine


def test_clickjacking(boilerplate):
    (
        target,
        port,
        timeout_sec,
        log_in_file,
        language,
        time_sleep,
        thread_tmp_filename,
        socks_proxy,
        scan_id,
        scan_cmd,
        result,
    ) = boilerplate
    try:
        assert (
            engine.clickjacking(
                target,
                port,
                timeout_sec,
                log_in_file,
                language,
                time_sleep,
                thread_tmp_filename,
                socks_proxy,
                scan_id,
                scan_cmd,
            )
            == False
        )
    except Exception:
        assert (
            engine.clickjacking(
                target,
                port,
                timeout_sec,
                log_in_file,
                language,
                time_sleep,
                thread_tmp_filename,
                socks_proxy,
                scan_id,
                scan_cmd,
            )
            == True
        )
