from nettacker.config import Config


def read_from_file(file_path):
    return open(Config.path.payloads_dir / file_path).read().split("\n")
