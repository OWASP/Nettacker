import ssl
from pathlib import Path

# Define directory paths for tests/common.py
nettacker_dir = str(Path(__file__).parent.parent)
tests_dir = str(Path(__file__).parent)

def pytest_configure():
    """
    Provide a compatibility shim for older tests that expect ssl.wrap_socket.
    Python 3.12 removed ssl.wrap_socket; tests should ideally mock SSLContext.wrap_socket.
    This shim only exists during test runs and does not affect production code.
    """
    if not hasattr(ssl, "wrap_socket"):
        def _wrap_socket(sock, *args, **kwargs):
            ctx = ssl.create_default_context()
            return ctx.wrap_socket(sock, *args, **kwargs)
        ssl.wrap_socket = _wrap_socket
