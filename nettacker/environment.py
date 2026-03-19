"""Environment and system requirements validation for Nettacker."""

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
    
    This function is called at module import time to fail-fast before
    any complex initialization occurs.
    """
    if not is_python_version_supported():
        from nettacker.core.die import die_failure
        from nettacker.core.messages import messages as _
        
        python_version = sys.version_info
        current_version = f"{python_version.major}.{python_version.minor}"
        die_failure(_("error_python_version").format(current_version))


# Run the version check immediately when this module is imported.
# Skip during testing to allow test suite to run and verify the check logic.
if "pytest" not in sys.modules:
    check_python_version()
