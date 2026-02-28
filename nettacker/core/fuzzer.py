from nettacker.config import Config


def read_from_file(file_path):
    with open(Config.path.payloads_dir / file_path) as payload_file:
        return payload_file.read().split("\n")
