"""Pre-load static HTML, CSS, and JS assets used to render HTML log reports."""

from nettacker.config import Config


def _read_file(path):
    """Read and return the entire contents of a file.

    Args:
        path: Path to the file to read.

    Returns:
        The file contents as a string.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    with open(path) as f:
        return f.read()


css_1 = _read_file(Config.path.web_static_dir / "report/html_table.css")
json_parse_js = _read_file(Config.path.web_static_dir / "report/json_parse.js")
table_end = _read_file(Config.path.web_static_dir / "report/table_end.html")
table_items = _read_file(Config.path.web_static_dir / "report/table_items.html")
table_title = _read_file(Config.path.web_static_dir / "report/table_title.html")
