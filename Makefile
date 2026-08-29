check: pre-commit test

package:
	rm -rf dist
	poetry build --no-interaction

pre-commit:
	pre-commit run --all-files

test: test-unit test-package

test-package: package
	poetry run pytest tests/package --no-cov -o addopts=

test-unit:
	poetry run pytest tests/unit
