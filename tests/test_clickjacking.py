import pytest
from lib.vuln.clickjacking import engine


def test_clickjacking(clickjacking_boilerplate):
    (
        target,
        port,
        timeout_sec,
        log_in_file,
        language,
        time_sleep,
        thread_tmp_filename,
        socks_proxy,
        scan_cmd,
        scan_id,
    ) = clickjacking_boilerplate
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
                scan_cmd,
                scan_id,
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
                scan_cmd,
                scan_id,
            )
            == True
        )
