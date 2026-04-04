# Validate environment and Python version first (fail-fast on import)
from nettacker import environment

# Perform Python version / environment validation at import time.
# Any skip logic (e.g., via env vars) should be implemented in
# nettacker.environment.ensure_supported_python().
environment.ensure_supported_python()
all_module_severity_and_desc = {}
