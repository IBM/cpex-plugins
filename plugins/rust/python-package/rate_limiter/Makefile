# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#   Rate Limiter Engine - Makefile
#   High-performance rate limiter engine (Rust + PyO3)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
# help: Rate Limiter Engine (Rust + Python extension build & automation)
# ─────────────────────────────────────────────────────────────────────────

.PHONY: help
help:
	@grep '^# help\:' $(firstword $(MAKEFILE_LIST)) | sed 's/^# help\: //'

PACKAGE_NAME := cpex-rate-limiter
WHEEL_PREFIX := cpex_rate_limiter
CARGO := cargo
STUB_FILES := cpex_rate_limiter/__init__.pyi cpex_rate_limiter/rate_limiter_rust/__init__.pyi
WHEEL_DIR := ../../../../target/wheels

GREEN := \033[0;32m
YELLOW := \033[0;33m
NC := \033[0m

# =============================================================================
# 🔍 LINTING & FORMAT
# =============================================================================
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

# =============================================================================
# 🧪 TESTS
# =============================================================================
# help: sync                  - Install plugin development dependencies
# help: test                  - Run Rust unit tests and Python integration tests
# help: test-unit             - Run Rust unit tests
# help: test-verbose          - Run Rust tests with verbose output
# help: test-integration      - Run repo-level integration tests for rate_limiter
# help: test-all              - Alias for test
.PHONY: sync test test-unit test-verbose test-python test-all test-integration verify-stubs

sync:
	uv sync --dev

test-unit:
	@echo "$(GREEN)Running rate_limiter Rust tests...$(NC)"
	$(CARGO) test

test: test-unit test-integration

test-verbose:
	@echo "$(GREEN)Running rate_limiter Rust tests (verbose)...$(NC)"
	$(CARGO) test -- --nocapture

test-python:
	$(MAKE) test-integration

test-integration:
	@echo "$(GREEN)Running integration tests (Redis tests auto-skip without Docker)...$(NC)"
	CPEX_TEST_PLUGIN_HOOKS=1 uv run pytest ../../../tests/rate_limiter -v --asyncio-mode=auto

test-all: test

verify-stubs: stub-gen
	@git diff --exit-code -- $(STUB_FILES)

# =============================================================================
# 🛠 BUILD
# =============================================================================
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

# =============================================================================
# 📊 BENCHMARKS
# =============================================================================
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
	$(CARGO) bench --bench rate_limiter -- --save-baseline main

bench-compare:
	$(CARGO) bench --bench rate_limiter -- --baseline main

# =============================================================================
# 🧹 CLEANUP
# =============================================================================
.PHONY: clean clean-all

clean:
	$(CARGO) clean
	rm -rf target/ coverage/
	find . -name "*.whl" -delete

clean-all: clean

# =============================================================================
# 📚 DOCUMENTATION
# =============================================================================
.PHONY: doc doc-open

doc:
	$(CARGO) doc --no-deps --document-private-items

doc-open: doc
	$(CARGO) doc --no-deps --document-private-items --open

# =============================================================================
# 🔧 DEVELOPMENT HELPERS
# =============================================================================
# help: verify                - Verify plugin installation
# help: check-all             - Run fmt-check + clippy + Rust tests
# help: ci-build              - Run CI build/static verification without integration tests
# help: ci                    - Run the full CI-equivalent plugin verification flow
.PHONY: verify check-all ci-build ci pre-commit

verify:
	@uv run python -c "from cpex_rate_limiter import rate_limiter_rust; print('rate_limiter_rust available')" || echo "rate_limiter_rust not installed — run: make install"

check-all: fmt-check clippy test-unit
	@echo "$(GREEN)All checks passed$(NC)"

ci-build: check-all verify-stubs build bench-no-run install-wheel

ci: ci-build test-integration
	@echo "$(GREEN)CI verification passed$(NC)"

pre-commit: check-all

.DEFAULT_GOAL := help
