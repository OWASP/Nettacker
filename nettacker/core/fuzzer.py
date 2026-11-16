from nettacker.config import Config


def read_lines(path):
    """Read the file at `path` and return one entry per line.

    The final newline only ends the last line, so it does not add an empty
    entry. Blank lines inside the file are kept, like the empty-password line
    at the top of the bundled password list.
    """
    with open(path) as file:
        return file.read().removesuffix("\n").split("\n")


def read_from_file(file_path):
    return read_lines(Config.path.payloads_dir / file_path)
