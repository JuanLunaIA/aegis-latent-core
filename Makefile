# aegis-latent-core — developer convenience targets
.PHONY: help install dev lint type security test test-cov smoke build-rust clean

PYTHON   := python3
PIP      := pip install
PYTEST   := pytest
RUFF     := ruff
MYPY     := mypy
BANDIT   := bandit

help:
	@echo "Available targets:"
	@echo "  install     Install runtime dependencies"
	@echo "  dev         Install all development dependencies"
	@echo "  lint        Run ruff linter"
	@echo "  type        Run mypy type checker"
	@echo "  security    Run bandit SAST scan"
	@echo "  test        Run test suite"
	@echo "  test-cov    Run tests with coverage report (65% gate)"
	@echo "  smoke       Run scripts/smoke_test.sh against local server"
	@echo "  build-rust  Build aegis_rust_v2 extension (.so) via maturin"
	@echo "  clean       Remove build artifacts"

install:
	$(PIP) .

dev:
	$(PIP) ".[dev]"

lint:
	$(RUFF) check .
	$(RUFF) format --check .

type:
	$(MYPY) aegis/ --ignore-missing-imports

security:
	$(BANDIT) -r aegis/ -c pyproject.toml -ll

test:
	$(PYTEST) tests/ -v

test-cov:
	$(PYTEST) tests/ -v --cov=aegis --cov-report=term-missing --cov-report=xml --cov-fail-under=65

smoke:
	chmod +x scripts/smoke_test.sh
	./scripts/smoke_test.sh

build-rust:
	@command -v maturin >/dev/null 2>&1 || { echo "maturin not found: pip install maturin"; exit 1; }
	cd aegis_rust_v2 && maturin develop --release
	cp aegis_rust_v2/target/release/libaegis_rust.so aegis/proxy/aegis_rust.so

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	find . -name '*.pyc' -delete 2>/dev/null; true
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov coverage.xml .coverage
	rm -rf dist/ build/ *.egg-info/
