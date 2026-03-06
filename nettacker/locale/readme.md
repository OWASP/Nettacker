# OWASP Nettacker Language Library

OWASP Nettacker message libraries are stored in this folder.

## Translation Helper Script

A helper script `00_locale_key_audit.py` is available in this folder to detect missing keys in language YAML files.

### Usage examples

- `python 00_locale_key_audit.py`  → check all languages.
- `python 00_locale_key_audit.py bn fr`  → check only Bengali and French.
- `python 00_locale_key_audit.py bn --fix`  → add missing keys to Bengali with placeholder values.

All missing keys will be appended at the end of the target YAML file with:

```yaml
# Auto-inserted keys with placeholder values, fix before committing
KEY: "placeholder_value"