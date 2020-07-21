import pytest
from lib.scan.endpoint_ext import engine
from core.compatible import version


if version() == 3:
    from urllib.parse import urlparse
else:
    from urlparse import urlparse

timeout_sec = 3
log_in_file = "./test.html"
time_sleep = 3.0
language = "en"
verbose_level = 2
socks_proxy = None
retries = 3
thread_tmp_filename = "./thread"
extra_requirements = {
        "regex": [
            r"""(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^"|']{0,}|)))(?:"|')"""
        ],
    }

def get_parsed_output(target):
    target_details = urlparse(target)
    scheme = target_details.scheme
    domain = target_details.netloc
    endpoints = engine.endpoints_extract(target,
    timeout_sec,
    log_in_file,
    time_sleep,
    language,
    verbose_level,
    socks_proxy,
    retries,
    thread_tmp_filename,
    extra_requirements,
    domain,
    scheme,)
    return endpoints

def test_endpoint_ext():
    end = get_parsed_output("http://belbana.com/scripts/animations.js")
    temp = 1
    for i in end:
        if i in ["images/open_knop.jpg", "images/close_knop.jpg", 'images/header/header_01.jpg', 'images/slogans/01.png', 'images/header/header_02.jpg', 'images/slogans/02.png', 'images/slogans/03.png', 'images/header/header_03.jpg', 'images/slogans/04.png', 'images/slogans/05.png', 'images/slogans/06.png', 'images/header/header_04.jpg', 'images/slogans/07.png', 'images/slogans/08.png', 'images/slogans/09.png','images/header/header_05.jpg', 'images/slogans/10.png', 'images/header/header_06.jpg', 'images/slogans/11.png',  'images/header/header_07.jpg', 'images/slogans/12.png', 'images/header/header_08.jpg', 'images/slogans/13.png']:
            continue
        else:
            temp = 0
            assert False
    if temp == 1:
        assert True
    assert get_parsed_output("https://www.google.com/js/bg/521PoRGnh7h8BVOMyCpHrhejufpyvF5vdQBdJpCoVT0.js") == []