import pytest
from . import engine


def test_clickjacking():

    assert engine.clickjacking("https://google.com", 443, 3.0, "./test.html", "en", 0.0, "./thread", None, "nettacker.py -m clickjacking_vuln -i https://analysed.in", "7a088343646d486eddefa4028013a6b") == False

    assert engine.clickjacking("https://github.com", 443, 3.0, "./test.html", "en", 0.0, "./thread", None, "nettacker.py -m clickjacking_vuln -i http://3.12.66.171/hub/login", "6eaa4fd99a3a881b9a426be1014f6442") == False
    
    with pytest.raises(Exception):
        assert engine.clickjacking("http://52.198.49.156/", 443, 3.0, "./test.html", "en", 0.0, "./thread", None, "nettacker.py -m clickjacking_vuln -i http://52.198.49.156/", "6eaa4fd99a3a881b9a426be1014f6442") == True