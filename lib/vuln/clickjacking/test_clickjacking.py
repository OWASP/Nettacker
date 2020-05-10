import pytest
from . import engine


@pytest.mark.parametrize('target, port, timeout_sec, log_in_file, language, time_sleep, thread_tmp_filename, socks_proxy, scan_id, scan_cmd, result',
                        [
                            ("https://google.com", 443, 3.0, "./test.html", "en", 0.0, "./thread", None, "nettacker.py -m clickjacking_vuln -i https://google.com", "7a088343646d486eddefa4028013a6b", False),
                            ("https://github.com", 443, 3.0, "./test.html", "en", 0.0, "./thread", None, "nettacker.py -m clickjacking_vuln -i http://github.com", "6eaa4fd99a3a881b9a426be1014f6442", False),
                             ("http://52.198.49.156/", 443, 3.0, "./test.html", "en", 0.0, "./thread", None, "nettacker.py -m clickjacking_vuln -i http://52.198.49.156/", "6eaa4fd99a3a881b9a426be1014f6442", True)
                        ])
def test_clickjacking(target, port, timeout_sec, log_in_file, language, time_sleep, thread_tmp_filename, socks_proxy, scan_id, scan_cmd, result):

    if(not result):
        assert engine.clickjacking(target, port, timeout_sec, log_in_file, language, time_sleep, thread_tmp_filename, socks_proxy, scan_id, scan_cmd) == result
    else:
        with pytest.raises(Exception):
            assert engine.clickjacking(target, port, timeout_sec, log_in_file, language, time_sleep, thread_tmp_filename, socks_proxy, scan_id, scan_cmd) == result

