# Aegis Audit Dashboard

This is a read-only Next.js interface for the primary Aegis proxy. It renders only values returned by the configured deployment. It does not import sample builders, invent audit rows, or synthesize historical metrics.

## Configuration

Set server-side environment variables before `npm run build`/`npm start`:

```bash
export AEGIS_PRIMARY_BASE_URL='https://aegis.internal'
export AEGIS_DASHBOARD_API_KEY='read-only-audit-token'
npm ci
npm run build
npm start
```

`AEGIS_DASHBOARD_API_KEY` is read only by explicit server route handlers and is never returned to browser JavaScript. Deploy behind an authenticated reverse proxy. Use a dedicated least-privilege audit key; this dashboard contains no mutation or export actions.

## Surfaces

The Overview reads `/health`, `/ready`, `/v1/audit/health`, and `/v1/audit/integrity`. The Ledger reads the real offset-based retained memory window and offers a bounded-DOM virtual view plus a native-table accessibility mode. The MMR page retrieves `/v1/audit/proofs/{state_id}` and runs the shared TypeScript verifier in the browser. Metrics parses an allowlist from the current `/metrics` scrape and never represents a snapshot as history.

## Honest limitations

Offset pagination is not snapshot-stable under concurrent appends or eviction. Integrity is labeled as a retained-memory-window result unless full history is retained. The MMR root returned by the same gateway is not an independent trust anchor. `/metrics` has no historical query contract; charts show current values only. If an endpoint is absent, empty, unauthorized, malformed, stale, or unavailable, the corresponding state is shown rather than replaced with zero or demo data.

## Verification

```bash
npm ci
npm run typecheck
npm test
npm run build
npm audit --audit-level=high
```
