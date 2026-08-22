# Dashboard Visual QA — Commercial Phase 2

**Date:** 2026-08-21 UTC  
**Target:** local Next.js dashboard at `127.0.0.1:3011`, connected server-side to a local real Aegis application at `127.0.0.1:8011` with one durably committed audit record.

The Overview rendered live `/health`, `/ready`, `/v1/audit/health`, and `/v1/audit/integrity` results in three responsive cards. The gateway returned `healthy`, readiness returned `ready`, the audit subsystem returned `ok` with one retained node, and retained-window integrity returned verified. A visual defect that initially colored `healthy` as failure was corrected by accepting the backend's actual healthy vocabulary.

The Ledger rendered the real audit record in the virtualized grid with explicit offset-window limitations, disabled forward pagination at the one-row boundary, and exposed the native accessible-table toggle. The row detail button opened a native modal dialog with state ID, full node hash, Merkle root, tenant, model/endpoint, signature scheme/status, and PHI scrub state. The modal backdrop and focusable close action rendered correctly.

The MMR page began in an explicit no-proof state. Submitting the real `dashboard-qa-record` identifier retrieved the persisted proof through the BFF and verified it with the shared Web Crypto implementation. The UI reported a valid inclusion proof, leaf ordinal `0 of 1`, the real leaf digest/root, valid signature status, the zero-length sibling path, and the single height-zero peak. It also retained the independent-root trust-boundary warning.

The Metrics page received HTTP 404 from the optional backend endpoint and rendered **Telemetry unavailable**. It did not convert absence to zero, fabricate samples, or render a fake trend.

A Next development-only CSP error was observed because Next requires `eval` for dev reconstruction. The configuration was corrected to include `unsafe-eval` only when `NODE_ENV=development`; production CSP remains without `unsafe-eval`. No production data or secrets were used in browser JavaScript.

A final Overview reload after the fixes showed all three healthy states in green and no Next development issue badge. The CSP correction therefore removed the observed development console error while preserving the production-only restriction.
