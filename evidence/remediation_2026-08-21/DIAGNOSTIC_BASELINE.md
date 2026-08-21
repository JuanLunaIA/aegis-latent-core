# Remediation Diagnostic Baseline — 2026-08-21

## Python 3.11 hang

The post-merge CI runs `32439758065` and `32439758104` stalled in Python 3.11 while Python 3.12 and 3.13 completed. A local CPython 3.11 reproduction isolated the hang to `TestClient` lifespan shutdown while analysis workers remained in the `asyncio.wait_for(asyncio.to_thread(...))` path. Excluding `tests/test_app_coverage_extended.py` completed 5,364 tests; isolated tests passed, establishing a timing-dependent teardown race rather than general runner slowness. The causal source boundaries were `aegis/proxy/app.py` worker processing and unlimited `gather` shutdown.

## Security alert API visibility

The active GitHub App user token reaches the repository and the authenticated user has repository administration permission, but GET requests for Dependabot, code-scanning, and secret-scanning alerts return HTTP 403 `Resource not accessible by integration`. Required fine-grained permissions are documented by GitHub as `Dependabot alerts: read`, `Code scanning alerts: read`, and `Secret scanning alerts: read`; writes require the corresponding `write` permission. Sources:

- https://docs.github.com/en/rest/dependabot/alerts
- https://docs.github.com/en/rest/code-scanning/code-scanning
- https://docs.github.com/en/rest/secret-scanning/secret-scanning
- https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app

The existing token cannot self-elevate; resolving this item requires GitHub App reauthorization or a new fine-grained credential supplied by an authorized owner. No alert count may be inferred from HTTP 403.

## Supply-chain baseline

The repository had 75 remote `uses:` occurrences across 24 distinct Action references and none used a 40-character commit SHA. Branch protection required six checks, one approval, CODEOWNERS, linear history, and resolved conversations; it did not enforce administrators or signed commits. Actions allowed all publishers and did not require SHA pinning. Dependabot covered pip, Cargo, Actions, and Docker, but automatic security fixes were disabled and configured labels did not exist.

## Warnings and response buffering

The local suite reproduced 5,442 passed, 37 skipped, and 47 warnings. Forty-four warnings came from repository tests using `datetime.utcnow()`; three came from FastAPI/Starlette and ldap3/pyasn1. The chat SSE path accumulated every normalized chunk and logprob, then joined the entire body before committing evidence. It had no byte or total-duration limit. The ML-KEM helpers remain optional in-process components and are not an authenticated production transport.

## Falsification boundaries

The Python diagnosis is falsified if a clean CPython 3.11 run still hangs after the cancellation regression and bounded teardown pass repeatedly. The streaming mitigation is falsified if an N+1 byte response is accepted, a slow-drip response outlives its total deadline, or the upstream async generator is not closed. The supply-chain result is falsified if any remote workflow reference is not a full 40-character SHA. The alert-visibility conclusion is falsified only by successful HTTP 200 responses using an authorized token.
