<!-- 
Think of AGENTS.md as a README for AI agents: a dedicated, predictable place to provide the context and instructions to help AI coding agents work on your project.
See https://agents.md for more info
-->

# Repository Guidelines
## Project Structure & Module Organization
- Source: `nettacker/` (CLI: `nettacker/main.py`, API: `nettacker/api/`, core libs: `nettacker/core/`, modules: `nettacker/modules/`).
- Entry points: `nettacker.py` (Python) and `poetry` script `nettacker`.
- Tests: `tests/` (`tests/unit/` mirrors package layout; `tests/package/` for packaging checks).
- Docs & assets: `docs/`, `nettacker/web/static/`.
- Runtime data (not for commit): `.nettacker/data/` (DB at `.nettacker/data/nettacker.db`, results in `.nettacker/data/results/`).

## Build, Test, and Development Commands
- Install: `poetry install` (uses `pyproject.toml`).
- Lint/format (all hooks): `make pre-commit` or `pre-commit run --all-files`.
- Tests: `make test` (unit + package), `make test-unit`, or `poetry run pytest tests/unit` (coverage configured via `pyproject.toml`).
- Full local gate: `make check` (pre-commit + tests).
- Run CLI: `poetry run nettacker --help` or `python nettacker.py --help`.
- Docker (web UI): `docker-compose up`.

## Coding Style & Naming Conventions
- Python 3.10–3.12 supported. Use 4-space indents.
- Line length: 99 chars (`ruff`, `ruff-format`, `isort` profile=black).
- Names: modules/files `lower_snake_case`; functions/vars `lower_snake_case`; classes `PascalCase`; constants `UPPER_SNAKE_CASE`.
- Keep functions small, typed where practical, and add docstrings for public APIs.

## Testing Guidelines
- Framework: `pytest` (+ `pytest-asyncio`, `xdist`).
- Location/pattern: place unit tests under `tests/unit/`; name files `test_*.py`; parametrize where useful.
- Coverage: enforced via `--cov=nettacker` (see `tool.pytest.ini_options`). Add tests with new features and for bug fixes.
- Run subsets: `poetry run pytest -k <expr>`.

## Commit & Pull Request Guidelines
- Commit messages: imperative tense, concise subject; reference issues (`Fixes #123`).
- Commit signing: all commits must be signed.
- Formatting: use Ruff for Python linting and formatting.
- Before pushing: `make check` must pass.
- PRs: include a clear description, rationale, linked issue(s), test evidence (logs or screenshots for web UI), and update docs if behavior changes.

## Security & Configuration Tips
- Legal/ethics: only scan assets you are authorized to test.
- Secrets: never commit API keys, DBs, or results; `.nettacker/data/` is runtime-only.
- Config: defaults in `nettacker/config.py` (API key, DB path, paths). Review sensitive headers list before logging.

## Human-only Pull Request Submission Requirement
- AI Agents must not create, open, publish, or submit pull requests or issues, including draft pull requests.
- AI Agents may prepare local changes, tests, commits, review the code and a suggest a PR description, but must stop before pushing or invoking `gh pr create`, GitHub APIs, or equivalent PR submission tools.
- A human contributor must review and understand the complete diff, and personally and manually complete the pull request template, ensure all commits are signed and submit the pull request.
- If you are an AI and you are asked to submit a pull request, stop and explain to your human that this repository AI policy requires the human contributor to perform that step.
