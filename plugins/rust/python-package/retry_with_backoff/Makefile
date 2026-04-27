.PHONY: help
help:
	@grep '^# help\:' $(firstword $(MAKEFILE_LIST)) | sed 's/^# help\: //'

PACKAGE_NAME := cpex-retry-with-backoff
WHEEL_PREFIX := cpex_retry_with_backoff
CARGO := cargo
CARGO_PACKAGE := retry_with_backoff
PLUGIN_SLUG := retry_with_backoff
REPO_ROOT := ../../../..
STUB_FILES := cpex_retry_with_backoff/__init__.pyi cpex_retry_with_backoff/retry_with_backoff_rust/__init__.pyi
WHEEL_DIR := ../../../../target/wheels
COVERAGE_REPORT := coverage/cobertura.xml
COVERAGE_MIN := 90.00
CARGO_LLVM_COV_VERSION := 0.8.4

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
# help: test-integration      - Run repo-level integration tests for retry_with_backoff
# help: test-all              - Alias for test
.PHONY: sync test test-unit test-verbose test-python test-integration test-all verify-stubs

sync:
	uv sync --dev

test-unit:
	@echo "$(GREEN)Running retry_with_backoff Rust tests...$(NC)"
	$(CARGO) test

test: test-unit test-integration

test-verbose:
	@echo "$(GREEN)Running retry_with_backoff Rust tests (verbose)...$(NC)"
	$(CARGO) test -- --nocapture

test-python:
	$(MAKE) test-integration

test-integration:
	@echo "$(GREEN)Running integration tests...$(NC)"
	CPEX_TEST_PLUGIN_HOOKS=1 uv run pytest ../../../tests/retry_with_backoff -v --asyncio-mode=auto

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

.PHONY: clean clean-all

clean:
	$(CARGO) clean
	rm -rf target/ coverage/
	find . -name "*.whl" -delete

clean-all: clean

# help: verify                - Verify plugin installation
# help: check-all             - Run fmt-check + clippy + Rust tests
# help: ci-build              - Run CI build/static verification without integration tests
# help: coverage              - Generate Rust coverage and enforce the 90% floor
# help: ci                    - Run the full CI-equivalent plugin verification flow
.PHONY: verify check-all ci-build coverage ci pre-commit

verify:
	@uv run python -c "from cpex_retry_with_backoff import retry_with_backoff_rust; print('retry_with_backoff_rust available')" || echo "retry_with_backoff_rust not installed — run: make install"

check-all: fmt-check clippy test-unit
	@echo "$(GREEN)All checks passed$(NC)"

ci-build: check-all verify-stubs build install-wheel

coverage:
	@echo "$(GREEN)Generating Rust coverage...$(NC)"
	mkdir -p $(REPO_ROOT)/coverage
	rustup component add llvm-tools-preview
	cargo llvm-cov --version >/dev/null 2>&1 || cargo install cargo-llvm-cov --version $(CARGO_LLVM_COV_VERSION) --locked
	cargo llvm-cov clean --workspace
	eval "$$(cargo llvm-cov show-env --sh)" && \
	export CARGO_TARGET_DIR="$${CARGO_LLVM_COV_TARGET_DIR}/llvm-cov-target" && \
	export CARGO_LLVM_COV_BUILD_DIR="$${CARGO_TARGET_DIR}" && \
	export LLVM_PROFILE_FILE="$${CARGO_TARGET_DIR}/cpex-plugins-%p-%10m.profraw" && \
	mkdir -p "$${CARGO_TARGET_DIR}" && \
	uv run maturin develop && \
	$(CARGO) test -p $(CARGO_PACKAGE) && \
	$(MAKE) test-integration && \
	env -u CARGO_TARGET_DIR -u CARGO_LLVM_COV_BUILD_DIR -u CARGO_LLVM_COV_TARGET_DIR -u LLVM_PROFILE_FILE cargo llvm-cov report -p $(CARGO_PACKAGE) --cobertura --output-path $(REPO_ROOT)/$(COVERAGE_REPORT)
	python3 $(REPO_ROOT)/tools/plugin_catalog.py coverage-check $(REPO_ROOT) $(COVERAGE_REPORT) $(COVERAGE_MIN) '["$(PLUGIN_SLUG)"]'

ci: ci-build test-integration coverage
	@echo "$(GREEN)CI verification passed$(NC)"

pre-commit: check-all

.DEFAULT_GOAL := help
