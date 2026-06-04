## Summary

<!-- One-sentence description of what this PR does. -->

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Security fix
- [ ] Documentation update
- [ ] Refactor / code quality

## Checklist

- [ ] `ruff check .` passes with zero violations
- [ ] `mypy aegis/` passes with zero errors
- [ ] `pytest tests/ --cov=aegis --cov-fail-under=85` passes
- [ ] `bandit -r aegis/ -c pyproject.toml -ll` passes
- [ ] New tests added for changed behavior (if applicable)
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] `SECURITY.md` updated if any security-relevant change

## Test plan

<!-- Describe how you tested this change. Include commands run. -->

## Security considerations

<!-- Any security implications? Briefly describe attack surface changes, if any. -->
