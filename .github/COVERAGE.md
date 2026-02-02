# Coverage Reporting

## Overview
Nettacker uses pytest-cov and coverage.py to track code coverage. The project aims for **70% code coverage** as a quality goal.

## Local Development

### Run tests with coverage
```bash
make test
```

### Generate HTML coverage report
```bash
coverage html
open htmlcov/index.html  # macOS/Linux
start htmlcov/index.html # Windows
```

### View coverage summary
```bash
coverage report
```

## CI/CD Integration

### What's generated in CI
- **XML Report** (`coverage.xml`): Used by Codecov for badge generation and trend tracking
- **HTML Report** (`htmlcov/`): Human-readable, uploaded as GitHub Actions artifact
- **Terminal Output**: Shown in CI logs during test run

### Where to find coverage reports

1. **Codecov Dashboard** (once configured):
   - Badge on README
   - Detailed file/line coverage
   - Coverage trends over time
   - PR comments with coverage diff

2. **GitHub Actions Artifacts**:
   - Go to Actions → Select workflow run → Scroll to "Artifacts"
   - Download `coverage-report` to view HTML locally

3. **CI Logs**:
   - Check test job output for coverage percentage summary

## Configuration

Coverage settings are in [pyproject.toml](../pyproject.toml):

```toml
[tool.pytest.ini_options]
addopts = "--cov=nettacker --cov-config=pyproject.toml --cov-report term --cov-report xml ..."

[tool.coverage.run]
branch = true
```

## Setup Codecov (Project Maintainers)

1. Sign up at [codecov.io](https://codecov.io)
2. Link your GitHub repository
3. Add `CODECOV_TOKEN` to repository secrets
4. Coverage badge will appear automatically

## Monitoring Coverage

- **PR Reviews**: Check coverage changes before merging
- **Coverage Trends**: Monitor overall project coverage percentage
- **Identify Gaps**: Use HTML report to find untested code
- **Set Targets**: Work toward 70% coverage goal
