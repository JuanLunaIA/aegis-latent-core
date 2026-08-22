"use client";

import { useEffect, useState } from "react";

interface OverviewData {
  readonly health: {readonly status: string}; readonly ready: {readonly status: string};
  readonly audit: {readonly status: string; readonly node_count: number; readonly fault_state: string; readonly full_history_retained?: boolean};
  readonly integrity: {readonly valid: boolean; readonly node_count: number; readonly scope: string; readonly full_history_retained: boolean};
  readonly fetched_at: string;
}

type ViewState = {kind: "loading"} | {kind: "error"; message: string} | {kind: "ready"; data: OverviewData};

function Status({ok, children}: Readonly<{ok: boolean; children: React.ReactNode}>) {
  return <p className={`status ${ok ? "good" : "bad"}`}>{children}</p>;
}

export function OverviewPanel() {
  const [state, setState] = useState<ViewState>({kind: "loading"});
  async function load() {
    setState({kind: "loading"});
    try {
      const response = await fetch("/api/aegis/overview", {cache: "no-store"});
      const value = await response.json() as OverviewData & {error?: string};
      if (!response.ok) throw new Error(value.error ?? "Overview unavailable");
      setState({kind: "ready", data: value});
    } catch (error) {
      setState({kind: "error", message: error instanceof Error ? error.message : "Overview unavailable"});
    }
  }
  useEffect(() => {void load();}, []);
  if (state.kind === "loading") return <div aria-live="polite"><p>Loading verified service state…</p><div className="grid"><div className="skeleton"/><div className="skeleton"/><div className="skeleton"/></div></div>;
  if (state.kind === "error") return <section className="notice error" role="alert"><h2>Overview unavailable</h2><p>{state.message}</p><button onClick={() => void load()}>Retry</button></section>;
  const {data} = state;
  return <><div className="grid">
    <section className="card"><h2>Gateway</h2><Status ok={["ok","healthy"].includes(data.health.status)}>{data.health.status}</Status><p>Readiness: {data.ready.status}</p></section>
    <section className="card"><h2>Audit subsystem</h2><Status ok={data.audit.status === "ok"}>{data.audit.status}</Status><p>{data.audit.node_count.toLocaleString()} nodes in the retained memory window.</p></section>
    <section className="card"><h2>Window integrity</h2><Status ok={data.integrity.valid}>{data.integrity.valid ? "Verified" : "Failed"}</Status><p>Scope: {data.integrity.scope}</p></section>
  </div>
  {!data.integrity.full_history_retained && <aside className="notice"><strong>Bounded window:</strong> older nodes exist outside this in-memory view. This result is not a full-history sweep.</aside>}
  <p className="muted">Last fetched: <time dateTime={data.fetched_at}>{new Date(data.fetched_at).toLocaleString()}</time></p></>;
}
