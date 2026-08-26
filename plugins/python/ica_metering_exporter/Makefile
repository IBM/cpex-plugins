.PHONY: sync test test-unit test-integration test-all check-all build install ci-build ci clean

sync:
	uv sync --dev

test: test-unit

test-unit:
	uv run pytest tests/ -v

test-integration:
	CPEX_TEST_PLUGIN_HOOKS=1 uv run pytest ../../tests/ica_metering_exporter -v

test-all: test test-integration

check-all:
	uv run ruff format --check .
	uv run ruff check .
	uv run mypy cpex_ica_metering_exporter tests

build:
	uv build --project . --out-dir ./dist

install:
	uv pip install -e .

ci-build: check-all test build

ci: ci-build test-integration

clean:
	rm -rf .mypy_cache .pytest_cache .ruff_cache build dist
