from nettacker.config import Config


def read_from_file(file_path):
    return (Config.path.payloads_dir / file_path).read_text(encoding="utf-8").split("\n")
