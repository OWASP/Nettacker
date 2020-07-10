import pytest
from lib.vuln.crlf import engine


def test_crlf(crlf_boilerplate):
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
    ) = crlf_boilerplate
    if engine.__crlf(
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
    ):
        assert True
    else:
        assert False