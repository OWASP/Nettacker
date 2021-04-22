from pytest import fixture


reqs_clickjacking = [
    (
        "https://flipkart.com",
        443,
        3.0,
        "./test.html",
        "en",
        0.0,
        "./thread",
        None,
        "nettacker.py -m clickjacking_vuln -i http://flipkart.com",
        "6eaa4fd99a3a881b9a426be1014f6442",
    ),
    (
        "http://52.198.49.156/",
        80,
        3.0,
        "./test.html",
        "en",
        0.0,
        "./thread",
        None,
        "nettacker.py -m clickjacking_vuln -i http://52.198.49.156/",
        "6eaa4fd99a3a881b9a426be1014f6442",
    ),
    (
        "http://72.15.57.35:10443",
        10443,
        3.0,
        "./test.html",
        "en",
        0.0,
        "./thread",
        None,
        "nettacker.py -m clickjacking_vuln -i http://52.198.49.156/",
        "6eaa4fd99a3a881b9a426be1014f6442",
    ),
]

reqs_crlf = [
    (
        "https://ac611f591e4f78de80ff42fc004e0028.web-security-academy.net/",
        443,
        3.0,
        "./test.html",
        "en",
        0.0,
        "./thread",
        None,
        "6eaa4fd99a3a881b9a426be1014f6442",
        "nettacker.py -m clickjacking_vuln -i http://flipkart.com",
    ),
    (
        "http://uber.com",
        80,
        3.0,
        "./test.html",
        "en",
        0.0,
        "./thread",
        None,
        "6eaa4fd99a3a881b9a426be1014f6442",
        "nettacker.py -m clickjacking_vuln -i http://52.198.49.156/",
    )
]

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
}
reqs_wayback = [
    (
        "https://uber.com",
        3.0,
        "./test.html",
        0.0,
        "en",
        0,
        None,
        3,
        headers,
        "./thread",
        {"extensions": [""]}
    ),
    (
        "xyz",
        3.0,
        "./test.html",
        0.0,
        "en",
        0,
        None,
        3,
        headers,
        "./thread",
        {"extensions": [""]}
    ),
]


check_valid_api_key = [
    (
        "google.com",
        2.0,
        "./test.html",
        0.0,
        "en",
        2,
        None,
        3,
        headers,
        "3pJIWkJ8O5sUOA64hxmO3bpG2V8BYVQN",
    ),
    ("google.com", 2.0, "./test.html", 0.0, "en", 2, None, 3, headers, "invalidapikey"),
    ("google.com", 2.0, "./test.html", 0.0, "en", 2, None, 3, headers, ""),
    ("google.com", 2.0, "./test.html", 0.0, "en", 2, None, 3, headers, 123),
]

check_inet_working_properly = [
    (
        "10.0.0.0/32",
        2.0,
        "./test.html",
        0.0,
        "en",
        2,
        None,
        3,
        headers,
        "3pJIWkJ8O5sUOA64hxmO3bpG2V8BYVQN",
    ),
]


@fixture(params=check_valid_api_key)
def apikeys(request):
    key = request.param
    yield key


@fixture(params=check_inet_working_properly)
def shodan_inet(request):
    key = request.param
    yield key


@fixture
def validapikey():
    return "3pJIWkJ8O5sUOA64hxmO3bpG2V8BYVQN"


@fixture(params=reqs_clickjacking)
def clickjacking_boilerplate(request):
    key = request.param
    yield key

@fixture(params=reqs_wayback)
def wayback_boilerplate(request):
    key = request.param
    yield key

@fixture(params=reqs_crlf)
def crlf_boilerplate(request):
    key = request.param
    yield key