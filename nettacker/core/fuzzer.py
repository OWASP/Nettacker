from base64 import b64encode

from requests.compat import quote

from nettacker.config import Config


def read_from_file(file_path):
    return open(Config.path.payloads_dir / file_path).read().split("\n")


def base64_encode(data):
    return b64encode(data.encode()).decode()


def url_encode(data):
    return quote(data)
