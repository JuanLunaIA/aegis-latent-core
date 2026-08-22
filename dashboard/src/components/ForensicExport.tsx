"use client";

import { useState } from "react";

type ExportState =
  | {readonly kind: "editing"}
  | {readonly kind: "review"}
  | {readonly kind: "exporting"}
  | {readonly kind: "error"; readonly message: string}
  | {readonly kind: "complete"; readonly filename: string};

interface Scope {
  readonly start: string;
  readonly end: string;
  readonly operator: string;
  readonly reason: string;
  readonly tenant: string;
}

const EMPTY_SCOPE: Scope = {start: "", end: "", operator: "", reason: "", tenant: ""};

function iso(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.valueOf())) throw new Error("Enter a valid start and end time.");
  return parsed.toISOString();
}

function filenameFrom(response: Response): string {
  const disposition = response.headers.get("content-disposition") ?? "";
  const match = /filename="([A-Za-z0-9._-]+)"/.exec(disposition);
  return match?.[1] ?? "aegis-forensic.zip";
}

export function ForensicExport() {
  const [scope, setScope] = useState<Scope>(EMPTY_SCOPE);
  const [state, setState] = useState<ExportState>({kind: "editing"});

  function field<K extends keyof Scope>(key: K, value: Scope[K]): void {
    setScope((current) => ({...current, [key]: value}));
    if (state.kind === "error" || state.kind === "complete") setState({kind: "editing"});
  }

  function review(): void {
    try {
      if (!scope.operator.trim() || !scope.reason.trim()) throw new Error("Operator and acquisition reason are required.");
      if (iso(scope.start) >= iso(scope.end)) throw new Error("Start time must precede end time.");
      setState({kind: "review"});
    } catch (error: unknown) {
      setState({kind: "error", message: error instanceof Error ? error.message : "Invalid export scope."});
    }
  }

  async function generate(): Promise<void> {
    setState({kind: "exporting"});
    try {
      const response = await fetch("/api/v1/forensics/export", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          start_time: iso(scope.start),
          end_time: iso(scope.end),
          operator: scope.operator.trim(),
          acquisition_reason: scope.reason.trim(),
          ...(scope.tenant.trim() ? {tenant_id: scope.tenant.trim()} : {}),
        }),
      });
      if (!response.ok) {
        const value = await response.json().catch((): {detail?: string; error?: string} => ({})) as {detail?: string; error?: string};
        throw new Error(value.detail ?? value.error ?? "The forensic export failed.");
      }
      const blob = await response.blob();
      const filename = filenameFrom(response);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename;
      anchor.click();
      URL.revokeObjectURL(url);
      setState({kind: "complete", filename});
    } catch (error: unknown) {
      setState({kind: "error", message: error instanceof Error ? error.message : "The forensic export failed."});
    }
  }

  return <section aria-labelledby="forensic-export-title">
    <h2 id="forensic-export-title">Evidence bundle scope</h2>
    <p className="notice">Exports contain sensitive retained audit metadata. The bundle is technical integrity evidence, not an ISO certification or legal-admissibility determination.</p>
    <div className="form-grid">
      <div><label htmlFor="export-start">Start time</label><input id="export-start" type="datetime-local" required value={scope.start} onChange={(event) => field("start", event.target.value)}/></div>
      <div><label htmlFor="export-end">End time</label><input id="export-end" type="datetime-local" required value={scope.end} onChange={(event) => field("end", event.target.value)}/></div>
      <div><label htmlFor="export-operator">Operator identity</label><input id="export-operator" required maxLength={200} value={scope.operator} onChange={(event) => field("operator", event.target.value)}/></div>
      <div><label htmlFor="export-tenant">Tenant ID (optional)</label><input id="export-tenant" maxLength={200} value={scope.tenant} onChange={(event) => field("tenant", event.target.value)}/></div>
    </div>
    <label htmlFor="export-reason">Acquisition reason</label>
    <textarea id="export-reason" required maxLength={500} value={scope.reason} onChange={(event) => field("reason", event.target.value)}/>
    {state.kind !== "review" && <button type="button" onClick={review} disabled={state.kind === "exporting"}>Review export</button>}
    {state.kind === "review" && <div className="notice" aria-labelledby="export-review-title">
      <h3 id="export-review-title">Confirm immutable scope</h3>
      <dl><dt>UTC range</dt><dd>{iso(scope.start)} to {iso(scope.end)}</dd><dt>Tenant</dt><dd>{scope.tenant.trim() || "All tenants authorized by this audit key"}</dd><dt>Operator</dt><dd>{scope.operator}</dd></dl>
      <div className="button-row"><button type="button" onClick={() => setState({kind: "editing"})}>Edit</button><button type="button" onClick={() => void generate()}>Generate and download ZIP</button></div>
    </div>}
    {state.kind === "exporting" && <p aria-live="polite">Generating bounded forensic bundle…</p>}
    {state.kind === "error" && <div className="notice error" role="alert"><h3>Export unavailable</h3><p>{state.message}</p></div>}
    {state.kind === "complete" && <div className="notice" role="status"><h3>Download created</h3><p>{state.filename} was prepared. Run VERIFY.sh after extracting the archive.</p></div>}
  </section>;
}
