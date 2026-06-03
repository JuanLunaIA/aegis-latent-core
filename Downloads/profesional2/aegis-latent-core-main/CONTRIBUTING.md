# Contributing to Aegis Latent Core

Thank you for contributing to Aegis Latent Core. This file explains the preferred workflow for issues, branches, PRs, tests, and general repo conventions.

Getting started
- Create a working environment: Python 3.11+, then:
  ```bash
  python -m venv .venv && . .venv/bin/activate
  pip install -e '.[dev]'
  ```
- Open an issue first for non-trivial changes or features so maintainers can provide guidance.

Branching & commits
- Branch naming: `feature/<short-desc>`, `fix/<short-desc>`, `chore/<short-desc>`.
- Commit messages: follow Conventional Commits (e.g., `feat: add X`, `fix: correct Y`, `chore: bump deps`).

Pull requests
- Open a PR against `main` with a clear description and link to the issue (if any).
- Include test coverage for new features and justify design decisions in the PR description.
- PRs should pass CI (tests, linting, type checks). Maintainters may request revisions.
- Request at least one approving review; for security-sensitive or large changes request additional reviewers.

Testing & quality checks
- Run tests locally:
  - Full suite: `make test` or `pytest tests/ -v`
  - Single file: `pytest tests/test_core.py -q`
  - Single test: `pytest tests/test_core.py::test_name -q`
- Lint & format: `make lint` (ruff check and format)
- Type checking: `make type` (mypy)
- Security scan (SAST): `make security` (bandit)

Adding dependencies
- Add runtime deps to `pyproject.toml` `dependencies` section and optional extras under `project.optional-dependencies`.
- Avoid pinning to overly-specific patch versions unless necessary. Update `requirements.txt` if present.
- Run tests and CI after adding dependencies; document heavy optional extras (vllm, hf, gpu).

Rust extension contributions
- `aegis_rust_v2` is built with `maturin`. To test locally:
  ```bash
  cd aegis_rust_v2
  maturin develop --release
  ```
- Ensure the produced artifact (e.g., `.so`) works with the Python build and that Python tests that require the extension still pass.

Documentation
- Update `README.md`, `DEPLOYMENT_GUIDE.md` and relevant docs for new features or changes to runtime configuration.

PR checklist (example)
- [ ] Linked issue (if applicable)
- [ ] Tests added/updated
- [ ] Linter/format checks passed (`make lint`)
- [ ] Type checks passed (`make type`)
- [ ] Documentation updated (README / DEPLOYMENT_GUIDE)
- [ ] CI green

Contact & security
- See `SECURITY.md` for reporting vulnerabilities. Do not include sensitive exploit details in a public issue.

Thanks for contributing — small, focused PRs with tests and clear justification are easiest to review.
