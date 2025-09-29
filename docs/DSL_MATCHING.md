# DSL (Domain Specific Language) Matching for Nettacker

## Overview

The DSL matching system provides advanced version comparison capabilities for CVE modules in Nettacker. This feature enables sophisticated version matching that goes beyond simple regex patterns, allowing for semantic version comparisons and complex version range evaluations.

## Features

### Version Comparison Operators
- `>=` - Greater than or equal to
- `<=` - Less than or equal to
- `>` - Greater than
- `<` - Less than
- `==` - Equal to (exact match)
- `!=` - Not equal to
- `~` - Tilde comparison (patch-level changes)
- `^` - Caret comparison (backward compatible changes)

### Special Patterns
- **Range expressions**: `1.0 to 2.0`, `1.0-2.0`
- **Multiple conditions**: `>=1.0.0,<2.0.0`
- **Wildcard patterns**: `1.2.*`, `1.?.3`
- **Semantic versioning**: Full support for semver rules

## Usage in YAML Modules

### Basic DSL Version Check

```yaml
response:
  condition_type: and
  conditions:
    version_dsl:
      patterns:
        - "Apache[/\\s]([0-9]+\\.[0-9]+\\.[0-9]+)"
        - "Server:\\s*Apache[/\\s]([0-9]+\\.[0-9]+\\.[0-9]+)"
      expressions:
        - ">=2.4.0"
        - "<2.4.58"
      reverse: false
```

### CVE-Specific Version Matching

```yaml
response:
  condition_type: and
  conditions:
    cve_version_match:
      patterns:
        - "nginx[/\\s]([0-9]+\\.[0-9]+\\.[0-9]+)"
      affected_versions:
        - "<1.20.0"
        - "1.18.*"
        - ">=1.16.0,<1.19.5"
      reverse: false
```

## Configuration Options

### `version_dsl` Condition
- **patterns** (list): Regex patterns to extract version from response
- **expressions** (list): DSL expressions to match against extracted version
- **reverse** (bool): Reverse the match result (default: false)

### `cve_version_match` Condition
- **patterns** (list): Regex patterns to extract version from response
- **affected_versions** (list): List of vulnerable version expressions
- **reverse** (bool): Reverse the match result (default: false)

## DSL Expression Examples

### Basic Comparisons
```yaml
expressions:
  - ">=2.4.0"        # Version 2.4.0 or higher
  - "<3.0.0"         # Version below 3.0.0
  - "==2.4.49"       # Exactly version 2.4.49
  - "!=1.0.0"        # Not version 1.0.0
```

### Range Expressions
```yaml
expressions:
  - "1.0 to 2.0"     # Between 1.0 and 2.0 (inclusive)
  - "2.4.0-2.4.58"   # Between 2.4.0 and 2.4.58
```

### Multiple Conditions
```yaml
expressions:
  - ">=2.4.0,<2.4.58"    # Version 2.4.0 to 2.4.57
  - ">1.0.0,!=1.5.0"     # Above 1.0.0 but not 1.5.0
```

### Semantic Versioning
```yaml
expressions:
  - "~1.2.3"         # >=1.2.3 <1.3.0 (patch level changes)
  - "^1.2.3"         # >=1.2.3 <2.0.0 (compatible changes)
```

### Wildcard Patterns
```yaml
expressions:
  - "1.2.*"          # Any version starting with 1.2.
  - "1.?.3"          # Version 1.x.3 (where x is any digit)
```

## Version Pattern Examples

### Common Server Headers
```yaml
patterns:
  - "Apache[/\\s]([0-9]+\\.[0-9]+\\.[0-9]+)"
  - "nginx[/\\s]([0-9]+\\.[0-9]+\\.[0-9]+)"
  - "Server:\\s*([^\\s]+)\\s*([0-9]+\\.[0-9]+\\.[0-9]+)"
```

### Application Versions
```yaml
patterns:
  - "WordPress ([0-9]+\\.[0-9]+\\.[0-9]+)"
  - "\\.js\\?ver=([0-9]+\\.[0-9]+\\.[0-9]+)"
  - "Version ([0-9]+\\.[0-9]+\\.[0-9]+)"
```

### Complex Version Patterns
```yaml
patterns:
  - "version[\"']?:\\s*[\"']?([0-9]+\\.[0-9]+\\.[0-9]+)"
  - "v([0-9]+\\.[0-9]+\\.[0-9]+(?:\\.[0-9]+)?)"
  - "([0-9]+\\.[0-9]+\\.[0-9]+(?:-[a-zA-Z0-9]+)?)"
```

## Complete Module Examples

### Apache CVE Module
```yaml
info:
  name: apache_cve_example
  author: OWASP Nettacker Team
  severity: 8
  description: Apache vulnerability using DSL matching

payloads:
  - library: http
    steps:
      - method: get
        url: "http://{target}/"
        response:
          condition_type: and
          conditions:
            cve_version_match:
              patterns:
                - "Apache[/\\s]([0-9]+\\.[0-9]+\\.[0-9]+)"
              affected_versions:
                - ">=2.4.0"
                - "<2.4.58"
              reverse: false
          log: "Apache {cve_version_match} is vulnerable"
```

### WordPress Security Check
```yaml
info:
  name: wordpress_security_dsl
  author: OWASP Nettacker Team
  severity: 7
  description: WordPress version security check

payloads:
  - library: http
    steps:
      - method: get
        url: "http://{target}/wp-admin/install.php"
        response:
          condition_type: and
          conditions:
            version_dsl:
              patterns:
                - "\\.css\\?ver=([0-9]+\\.[0-9]+\\.[0-9]+)"
              expressions:
                - "<6.4.0"
                - "^5.*"
              reverse: false
          log: "WordPress {version_dsl} may have vulnerabilities"
```

## Error Handling

The DSL matcher includes robust error handling:
- Invalid version strings are normalized automatically
- Fallback comparison methods for non-standard versions
- Graceful handling of malformed expressions
- Debug logging for troubleshooting

## Performance Considerations

- Version extraction patterns are compiled once per request
- DSL expressions are cached for repeated use
- Multiple version libraries provide fallback options
- Lightweight string operations for basic comparisons

## Best Practices

1. **Use specific patterns**: Make regex patterns as specific as possible to avoid false positives
2. **Test expressions**: Validate DSL expressions with known version strings
3. **Combine conditions**: Use multiple patterns and expressions for comprehensive coverage
4. **Handle edge cases**: Account for pre-release versions and build metadata
5. **Document assumptions**: Comment on expected version formats in modules

## Integration with Existing Modules

The DSL system is backward compatible with existing modules. You can:
- Add DSL conditions to existing modules
- Combine DSL with regex-based conditions
- Use both `version_dsl` and `cve_version_match` in the same module
- Gradually migrate from regex-only matching to DSL-enhanced matching
