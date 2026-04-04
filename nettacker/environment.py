"""Environment and system requirements validation for Nettacker."""

import os
import sys


def is_python_version_supported():
    """
    Check if the current Python version is supported.

    Nettacker requires Python 3.10-3.12 (inclusive).

    Returns:
        bool: True if the version is supported, False otherwise.
    """
    python_version = sys.version_info
    return python_version.major == 3 and 10 <= python_version.minor <= 12


def check_python_version():
    """
    Verify that the Python version is supported.

    Nettacker requires Python 3.10-3.12 (inclusive).
    Exits with a clean error message if the version is unsupported.
    """
    if not is_python_version_supported():
        from nettacker.core.die import die_failure
        from nettacker.core.messages import messages as _

        python_version = sys.version_info
        current_version = f"{python_version.major}.{python_version.minor}"
        die_failure(_("error_python_version").format(current_version))


def should_skip_python_version_check() -> bool:
    """
    Determine whether the Python version check should be skipped.

    This is intended primarily for testing or controlled environments.
    Set the environment variable ``NETTACKER_SKIP_PYTHON_VERSION_CHECK=1``
    to bypass the version check.
    """
    return os.getenv("NETTACKER_SKIP_PYTHON_VERSION_CHECK") == "1"


def ensure_supported_python():
    """
    Perform the Python version check unless explicitly skipped.

    This helper is safe to call from application entrypoints or at
    import time as part of package initialization.
    """
    if should_skip_python_version_check():
        return
    check_python_version()


# Perform environment validation when this module is imported,
# unless explicitly skipped via NETTACKER_SKIP_PYTHON_VERSION_CHECK.
ensure_supported_python()
