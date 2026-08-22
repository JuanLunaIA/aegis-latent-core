"use client";

import { useEffect, useState } from "react";

import { LedgerTable } from "@/components/LedgerTable";
import type { AuditNode } from "@/lib/contracts";

type State =
  | {readonly kind: "loading"}
  | {readonly kind: "error"; readonly message: string}
  | {readonly kind: "ready"; readonly nodes: AuditNode[]; readonly returned: number};
interface Filters {
  readonly tenant: string;
  readonly model: string;
  readonly endpoint: string;
  readonly policyViolations: boolean;
  readonly failuresOnly: boolean;
  readonly minLatency: string;
}

const PAGE = 200;
const EMPTY: Filters = {tenant: "", model: "", endpoint: "", policyViolations: false, failuresOnly: false, minLatency: ""};

function queryFor(offset: number, filters: Filters): URLSearchParams {
  const query = new URLSearchParams({offset: String(offset), limit: String(PAGE)});
  if (filters.tenant.trim()) query.set("tenant_id", filters.tenant.trim());
  if (filters.model.trim()) query.set("model", filters.model.trim());
  if (filters.endpoint.trim()) query.set("endpoint", filters.endpoint.trim());
  if (filters.policyViolations) query.set("phi_scrubbed", "true");
  if (filters.failuresOnly) query.set("failures_only", "true");
  if (filters.minLatency.trim()) query.set("min_latency_ms", filters.minLatency.trim());
  return query;
}

export function LedgerPanel() {
  const [offset, setOffset] = useState(0);
  const [draft, setDraft] = useState<Filters>(EMPTY);
  const [active, setActive] = useState<Filters>(EMPTY);
  const [state, setState] = useState<State>({kind: "loading"});

  async function load(nextOffset: number, filters: Filters): Promise<void> {
    setState({kind: "loading"});
    try {
      const response = await fetch(`/api/aegis/nodes?${queryFor(nextOffset, filters)}`, {cache: "no-store"});
      const value = await response.json() as {nodes?: AuditNode[]; returned?: number; error?: string};
      if (!response.ok || !value.nodes) throw new Error(value.error ?? "Ledger unavailable");
      setState({kind: "ready", nodes: value.nodes, returned: value.returned ?? value.nodes.length});
    } catch (error: unknown) {
      setState({kind: "error", message: error instanceof Error ? error.message : "Ledger unavailable"});
    }
  }

  useEffect(() => { void load(0, EMPTY); }, []);

  function update<K extends keyof Filters>(key: K, value: Filters[K]): void {
    setDraft((current) => ({...current, [key]: value}));
  }

  function apply(): void {
    const latency = draft.minLatency.trim();
    if (latency && (!Number.isFinite(Number(latency)) || Number(latency) < 0)) {
      setState({kind: "error", message: "High-latency threshold must be a non-negative number."});
      return;
    }
    setOffset(0);
    setActive(draft);
    void load(0, draft);
  }

  function clear(): void {
    setDraft(EMPTY);
    setActive(EMPTY);
    setOffset(0);
    void load(0, EMPTY);
  }

  return <>
    <form className="filters" onSubmit={(event) => { event.preventDefault(); apply(); }}>
      <div><label htmlFor="tenant">Tenant identifier</label><input id="tenant" value={draft.tenant} onChange={(event) => update("tenant", event.target.value)} maxLength={256}/></div>
      <div><label htmlFor="model">Model</label><input id="model" value={draft.model} onChange={(event) => update("model", event.target.value)} maxLength={256}/></div>
      <div><label htmlFor="endpoint">Provider endpoint</label><input id="endpoint" value={draft.endpoint} onChange={(event) => update("endpoint", event.target.value)} maxLength={256}/></div>
      <div><label htmlFor="latency">High latency at or above (ms)</label><input id="latency" inputMode="decimal" value={draft.minLatency} onChange={(event) => update("minLatency", event.target.value)} /></div>
      <label><input type="checkbox" checked={draft.policyViolations} onChange={(event) => update("policyViolations", event.target.checked)} style={{width: "auto", minHeight: "auto"}}/> PII/PHI policy events</label>
      <label><input type="checkbox" checked={draft.failuresOnly} onChange={(event) => update("failuresOnly", event.target.checked)} style={{width: "auto", minHeight: "auto"}}/> Terminal/invariant failures</label>
      <div className="button-row"><button type="submit">Apply filters</button><button type="button" onClick={clear}>Clear</button></div>
    </form>
    <p className="notice">This endpoint is an offset-based retained memory window. Rows can shift under concurrent appends or eviction; no stable snapshot is claimed.</p>
    {state.kind === "loading" && <p aria-live="polite">Loading audit nodes…</p>}
    {state.kind === "error" && <section className="notice error" role="alert"><h2>Ledger unavailable</h2><p>{state.message}</p><button onClick={() => void load(offset, active)}>Retry</button></section>}
    {state.kind === "ready" && <>
      <LedgerTable nodes={state.nodes}/>
      <div className="toolbar">
        <button disabled={offset === 0} onClick={() => { const next = Math.max(0, offset - PAGE); setOffset(next); void load(next, active); }}>Previous page</button>
        <button disabled={state.returned < PAGE} onClick={() => { const next = offset + PAGE; setOffset(next); void load(next, active); }}>Next page</button>
        <span aria-live="polite">Showing offset {offset}, {state.returned} returned.</span>
      </div>
    </>}
  </>;
}
