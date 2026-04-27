.PHONY: help
help:
	@grep '^# help\:' $(firstword $(MAKEFILE_LIST)) | sed 's/^# help\: //'

PACKAGE_NAME := cpex-content-moderation
WHEEL_PREFIX := cpex_content_moderation
WHEEL_DIR := ../../../../target/wheels

GREEN := \033[0;32m
YELLOW := \033[0;33m
NC := \033[0m

# help: fmt                   - Format Python code with black and isort
# help: fmt-check             - Check Python code formatting (CI)
# help: lint                  - Run ruff lints
.PHONY: fmt fmt-check lint

fmt:
	@echo "$(GREEN)Formatting Python code...$(NC)"
	uv run black . --line-length 200
	uv run isort . --profile black
	@echo "$(GREEN)Formatting complete$(NC)"

fmt-check:
	@echo "$(GREEN)Checking Python code formatting...$(NC)"
	uv run black . --line-length 200 --check
	uv run isort . --profile black --check-only

lint:
	@echo "$(GREEN)Running ruff lints...$(NC)"
	uv run ruff check . --select=E,F,W

type-check:
	@echo "$(GREEN)Running mypy type checks...$(NC)"
	uv run mypy cpex_content_moderation tests --ignore-missing-imports

# help: sync                  - Install plugin development dependencies
# help: test                  - Run Python tests
# help: test-verbose          - Run Python tests with verbose output
# help: test-all              - Run tests with coverage report
.PHONY: sync test test-verbose test-all

sync:
	uv sync --dev

test:
	@echo "$(GREEN)Running Content Moderation Plugin tests...$(NC)"
	uv run pytest tests/ -v

test-verbose:
	@echo "$(GREEN)Running tests with verbose output...$(NC)"
	uv run pytest tests/ -vv --tb=long

test-all:
	@echo "$(GREEN)Running tests with coverage report...$(NC)"
	uv run pytest tests/ -v --cov=cpex_content_moderation --cov-report=term-missing

# help: build                 - Build distribution wheel and source package
# help: install               - Install package in editable mode (for development)
# help: uninstall             - Uninstall the package
.PHONY: build install uninstall

build:
	@echo "$(GREEN)Building $(PACKAGE_NAME)...$(NC)"
	uv run python -m build
	@echo "$(GREEN)Build complete$(NC)"

install:
	@echo "$(GREEN)Installing $(PACKAGE_NAME) in editable mode...$(NC)"
	uv pip install -e .
	@echo "$(GREEN)Installation complete$(NC)"

uninstall:
	@echo "$(YELLOW)Uninstalling $(PACKAGE_NAME)...$(NC)"
	uv pip uninstall -y $(PACKAGE_NAME) 2>/dev/null || true

.PHONY: clean clean-all

clean:
	@echo "$(YELLOW)Cleaning build artifacts...$(NC)"
	rm -rf build/ dist/ *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache .coverage .mypy_cache

clean-all: clean
	@echo "$(YELLOW)Deep cleaning...$(NC)"
	rm -rf .venv venv .uv .uv.lock

# help: verify                - Verify plugin installation and basic imports
# help: check-all             - Run fmt-check + lint + type-check + tests
# help: ci                    - Run the full CI-equivalent plugin verification flow
.PHONY: verify check-all ci pre-commit

verify:
	@echo "$(GREEN)Verifying plugin can be imported...$(NC)"
	python -c "from cpex_content_moderation import ContentModerationPlugin; print('✓ Plugin loaded successfully')"

check-all: fmt-check lint type-check test
	@echo "$(GREEN)✓ All checks passed!$(NC)"

ci: check-all verify
	@echo "$(GREEN)✓ CI verification complete!$(NC)"

pre-commit: fmt lint test
