# aegis-latent-core — developer convenience targets
.PHONY: help install dev lint type security test test-cov smoke build-rust vendor-wheels docker-airgap clean

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
	@echo "  vendor-wheels Download all Python wheels for air-gapped build"
	@echo "  docker-airgap Build the air-gapped Docker image (requires vendor-wheels first)"
	@echo "  clean       Remove build artifacts"

install:
	$(PIP) -e .

dev:
	$(PIP) -e ".[dev]"

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

vendor-wheels:
	chmod +x scripts/vendor_wheels.sh
	./scripts/vendor_wheels.sh

docker-airgap: vendor-wheels
	@DIGEST=$$(cat vendor/python-3.11-slim-digest.txt 2>/dev/null || echo "sha256:c56af7e73c7b0cf23f4e83fa9c8acb0a63a5c10a3cd83f04c1f9dba3dd4d6d69"); \
	docker load < vendor/python-3.11-slim.tar.gz 2>/dev/null || true; \
	docker build --network=none \
	    --build-arg PYTHON_BASE_DIGEST=$$DIGEST \
	    -f deploy/docker/Dockerfile.airgap \
	    -t aegis-latent-core:3.0.1-airgap .

build-rust:
	@command -v maturin >/dev/null 2>&1 || { echo "maturin not found: pip install maturin"; exit 1; }
	cd aegis_rust_v2 && maturin develop --release
	cp aegis_rust_v2/target/release/libaegis_rust.so aegis/proxy/aegis_rust.so

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	find . -name '*.pyc' -delete 2>/dev/null; true
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov coverage.xml .coverage
	rm -rf dist/ build/ *.egg-info/
