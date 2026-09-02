# Aegis Audit Dashboard

This is a read-only Next.js interface for the primary Aegis proxy. It renders only values returned by the configured deployment. It does not import sample builders, invent audit rows, or synthesize historical metrics.

The dashboard consumes the unpublished v4 **`aegis-latent-sdk`** package from
`../sdk/typescript`. A clean checkout must install and build that sibling SDK
before installing or building the dashboard:

```bash
# Run from the repository root.
cd sdk/typescript
npm ci
npm run build

cd ../../dashboard
npm ci
```

Do not replace the `file:../sdk/typescript` dependency with an npm registry
install; the v4 SDK is not published. Keep commands in their indicated component
directories so each `npm ci` uses the correct lockfile. See the
[repository overview](../README.md), [developer quickstart](../docs/DEVELOPER_QUICKSTART.md),
and [platform operator guide](../docs/PLATFORM_OPERATOR_GUIDE.md) for canonical
project documentation.

## Configuration

Set server-side environment variables before `npm run build`/`npm start`:

```bash
export AEGIS_PRIMARY_BASE_URL='https://aegis.internal'
export AEGIS_DASHBOARD_API_KEY='read-only-audit-token'
npm run build
npm start
```

Run that block from `dashboard/`, after completing the sibling-SDK setup above.
For an interactive development server, use `npm run dev` instead of the final
two commands.

The current implementation reads `AEGIS_DASHBOARD_API_KEY` only in explicit server route handlers; the no-fabrication test also rejects exposure through a `NEXT_PUBLIC_*` variable. That test greps the source for the known mistake, so it is backed by a check on the build itself: `npm run check:bundle-secrets` (run after `npm run build`, and part of `npm run check`) scans everything the browser is served — `.next/static` plus prerendered `.html`/`.rsc` payloads — for the verbatim key value and for credential-shaped `NEXT_PUBLIC_*` names. Run it with the same environment as the build; it exits 2 rather than passing if there is no build output or no value to search for. CI runs it after the dashboard build with a placeholder key, so any inlining path leaves that placeholder in the output and fails the job. Deploy behind an authenticated reverse proxy and use a dedicated least-privilege audit key. The dashboard does not mutate ledger records, but its Forensics page can request and download a bounded evidence ZIP through the same-origin server route. That operation requires the backend `audit:export` scope and should be treated as sensitive data export.

## Surfaces

The Overview reads `/health`, `/ready`, `/v1/audit/health`, and `/v1/audit/integrity`. The Ledger reads the real offset-based retained memory window and offers a bounded-DOM virtual view plus a native-table accessibility mode. The MMR page retrieves `/v1/audit/proofs/{state_id}` and runs the shared TypeScript verifier in the browser. Metrics parses an allowlist from the current `/metrics` scrape and never represents a snapshot as history. Forensics proxies `POST /v1/audit/forensics/export` server-side and returns the bounded ZIP without exposing the backend bearer token to client code.

## Honest limitations

Offset pagination is not snapshot-stable under concurrent appends or eviction. Integrity is labeled as a retained-memory-window result unless full history is retained. The MMR root returned by the same gateway is not an independent trust anchor. `/metrics` has no historical query contract; charts show current values only. If an endpoint is absent, empty, unauthorized, malformed, stale, or unavailable, the corresponding state is shown rather than replaced with zero or demo data.

## Verification

After building `sdk/typescript` as shown above, run from `dashboard/`:

```bash
npm run typecheck
npm test
npm run build
npm audit --audit-level=high
```
