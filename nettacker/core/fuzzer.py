from nettacker.config import Config


def read_lines(path):
    # The trailing newline ends the last line, it is not an extra empty entry.
    with open(path) as file:
        return file.read().removesuffix("\n").split("\n")


def read_from_file(file_path):
    return read_lines(Config.path.payloads_dir / file_path)
