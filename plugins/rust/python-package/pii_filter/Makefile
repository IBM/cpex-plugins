.PHONY: help
help:
	@grep '^# help\:' $(firstword $(MAKEFILE_LIST)) | sed 's/^# help\: //'

PACKAGE_NAME := cpex-pii-filter
WHEEL_PREFIX := cpex_pii_filter
CARGO := cargo
STUB_FILES := cpex_pii_filter/__init__.pyi cpex_pii_filter/pii_filter_rust/__init__.pyi
WHEEL_DIR := ../../../../target/wheels

GREEN := \033[0;32m
YELLOW := \033[0;33m
NC := \033[0m

# help: fmt                   - Format Rust code with rustfmt
# help: fmt-check             - Check Rust code formatting (CI)
# help: clippy                - Run clippy lints
.PHONY: fmt fmt-check clippy

fmt:
	$(CARGO) fmt

fmt-check:
	$(CARGO) fmt -- --check

clippy:
	$(CARGO) clippy -- -D warnings

# help: sync                  - Install plugin development dependencies
# help: test                  - Run Rust unit tests and Python integration tests
# help: test-unit             - Run Rust unit tests
# help: test-verbose          - Run Rust tests with verbose output
# help: test-integration      - Run repo-level integration tests for pii_filter
# help: test-all              - Alias for test
.PHONY: sync test test-unit test-verbose test-python test-integration test-all verify-stubs

sync:
	uv sync --dev

test-unit:
	@echo "$(GREEN)Running pii_filter Rust tests...$(NC)"
	$(CARGO) test

test: test-unit test-integration

test-verbose:
	@echo "$(GREEN)Running pii_filter Rust tests (verbose)...$(NC)"
	$(CARGO) test -- --nocapture

test-python:
	$(MAKE) test-integration

test-integration:
	@echo "$(GREEN)Running Python tests...$(NC)"
	CPEX_TEST_PLUGIN_HOOKS=1 uv run pytest ../../../tests/pii_filter/test_integration.py -v -rs

test-all: test

verify-stubs: stub-gen
	@git diff --exit-code -- $(STUB_FILES)

# help: stub-gen              - Generate Python type stubs (.pyi files)
# help: build                 - Build release wheel (no install)
# help: install               - Build and install editable extension into project venv
# help: install-wheel         - Install the previously built wheel into project venv
.PHONY: stub-gen build install install-wheel uninstall

stub-gen:
	@echo "$(GREEN)Generating Python type stubs...$(NC)"
	$(CARGO) run --bin stub_gen
	@echo "$(GREEN)Stubs generated$(NC)"

build: stub-gen
	@echo "$(GREEN)Building $(PACKAGE_NAME)...$(NC)"
	uv run maturin build --release
	@echo "$(GREEN)Build complete$(NC)"

install: stub-gen
	@echo "$(GREEN)Installing $(PACKAGE_NAME)...$(NC)"
	uv run maturin develop --release
	@echo "$(GREEN)Installation complete$(NC)"

install-wheel: build
	@echo "$(GREEN)Installing built wheel for $(PACKAGE_NAME)...$(NC)"
	python3 ../../../../tools/install_built_wheel.py --wheel-dir "$(WHEEL_DIR)" --wheel-prefix "$(WHEEL_PREFIX)" --package-name "$(PACKAGE_NAME)" --venv-dir .venv
	@echo "$(GREEN)Wheel installation complete$(NC)"

uninstall:
	@echo "$(YELLOW)Uninstalling $(PACKAGE_NAME)...$(NC)"
	@uv pip uninstall -y $(PACKAGE_NAME) 2>/dev/null || true

# help: bench                 - Run Criterion benchmarks
# help: bench-no-run          - Compile Criterion benchmarks without running them
# help: bench-compare         - Compare against saved baseline
.PHONY: bench bench-no-run bench-baseline bench-compare

bench:
	@echo "$(GREEN)Running benchmarks...$(NC)"
	$(CARGO) bench

bench-no-run:
	@echo "$(GREEN)Compiling benchmarks without running them...$(NC)"
	$(CARGO) bench --no-run

bench-baseline:
	$(CARGO) bench --bench pii_filter -- --save-baseline main

bench-compare:
	$(CARGO) bench --bench pii_filter -- --baseline main

.PHONY: clean clean-all

clean:
	$(CARGO) clean
	rm -rf target/ coverage/
	find . -name "*.whl" -delete

clean-all: clean

# help: doc                   - Generate Rust documentation
# help: doc-open              - Generate and open documentation
.PHONY: doc doc-open

doc:
	$(CARGO) doc --no-deps --document-private-items

doc-open: doc
	$(CARGO) doc --no-deps --document-private-items --open

# help: verify                - Verify plugin installation
# help: check-all             - Run fmt-check + clippy + Rust tests
# help: ci-build              - Run CI build/static verification without integration tests
# help: ci                    - Run the full CI-equivalent plugin verification flow
.PHONY: verify check-all ci-build ci pre-commit

verify:
	@uv run python -c "from cpex_pii_filter import pii_filter_rust; print('pii_filter_rust available')" || echo "pii_filter_rust not installed — run: make install"

check-all: fmt-check clippy test-unit
	@echo "$(GREEN)All checks passed$(NC)"

ci-build: check-all verify-stubs build bench-no-run install-wheel

ci: ci-build test-integration
	@echo "$(GREEN)CI verification passed$(NC)"

pre-commit: check-all

.DEFAULT_GOAL := help
