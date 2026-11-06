from nettacker.config import Config


def read_from_file(file_path):
    # The trailing newline ends the last line, it is not an extra empty entry.
    return open(Config.path.payloads_dir / file_path).read().removesuffix("\n").split("\n")
