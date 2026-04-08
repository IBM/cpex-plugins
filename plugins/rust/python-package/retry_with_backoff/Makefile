.PHONY: help
help:
	@grep '^# help\:' $(firstword $(MAKEFILE_LIST)) | sed 's/^# help\: //'

PACKAGE_NAME := cpex-retry-with-backoff
WHEEL_PREFIX := cpex_retry_with_backoff
CARGO := cargo
STUB_FILES := cpex_retry_with_backoff/__init__.pyi cpex_retry_with_backoff/retry_with_backoff_rust/__init__.pyi
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
# help: test                  - Run Rust unit tests
# help: test-verbose          - Run Rust tests with verbose output
# help: test-python           - Run Python tests
# help: test-all              - Run both Rust and Python tests
.PHONY: sync test test-verbose test-python test-all verify-stubs

sync:
	uv sync --dev

test:
	@echo "$(GREEN)Running retry_with_backoff Rust tests...$(NC)"
	$(CARGO) test

test-verbose:
	@echo "$(GREEN)Running retry_with_backoff Rust tests (verbose)...$(NC)"
	$(CARGO) test -- --nocapture

test-python:
	@echo "$(GREEN)Running Python tests...$(NC)"
	uv run pytest tests/ -v

test-all: test test-python

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
# help: ci                    - Run the full CI-equivalent plugin verification flow
.PHONY: verify check-all ci pre-commit

verify:
	@uv run python -c "from cpex_retry_with_backoff import retry_with_backoff_rust; print('retry_with_backoff_rust available')" || echo "retry_with_backoff_rust not installed — run: make install"

check-all: fmt-check clippy test
	@echo "$(GREEN)All checks passed$(NC)"

ci: check-all verify-stubs build install-wheel test-python
	@echo "$(GREEN)CI verification passed$(NC)"

pre-commit: check-all

.DEFAULT_GOAL := help
