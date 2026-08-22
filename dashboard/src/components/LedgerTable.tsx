"use client";

import { useVirtualizer } from "@tanstack/react-virtual";
import { useEffect, useRef, useState } from "react";

import type { AuditNode, RawEvidence } from "@/lib/contracts";

function ShortValue({value, className = "hash"}: Readonly<{value: string; className?: string}>) {
  return <span className={className} title={value} aria-label={value}>{value.slice(0, 14)}…</span>;
}

function exactTime(timestamp: number): string {
  return new Date(timestamp * 1000).toISOString();
}

function Cells({node, onSelect}: Readonly<{node: AuditNode; onSelect: (node: AuditNode) => void}>) {
  return <>
    <span role="cell">{node.index}</span>
    <time role="cell" dateTime={exactTime(node.timestamp)}>{exactTime(node.timestamp)}</time>
    <span role="cell"><ShortValue value={node.cid} className="cid"/></span>
    <span role="cell" className="optional-col">{node.tenant_id}</span>
    <span role="cell" className="optional-col">{node.model}</span>
    <span role="cell">{node.token_count}</span>
    <span role="cell"><button onClick={() => onSelect(node)} aria-label={`Inspect audit node ${node.index}`}>Inspect</button></span>
  </>;
}

type EvidenceState =
  | {readonly kind: "loading"}
  | {readonly kind: "error"; readonly message: string}
  | {readonly kind: "ready"; readonly data: RawEvidence};

function NodeDialog({node, onClose}: Readonly<{node: AuditNode; onClose: () => void}>) {
  const ref = useRef<HTMLDialogElement>(null);
  const [evidence, setEvidence] = useState<EvidenceState>({kind: "loading"});
  useEffect(() => {
    ref.current?.showModal();
    void (async () => {
      try {
        const response = await fetch(`/api/aegis/evidence?node_hash=${node.node_hash}`, {cache: "no-store"});
        const value = await response.json() as RawEvidence & {error?: string};
        if (!response.ok) throw new Error(value.error ?? "Raw evidence unavailable");
        setEvidence({kind: "ready", data: value});
      } catch (error: unknown) {
        setEvidence({kind: "error", message: error instanceof Error ? error.message : "Raw evidence unavailable"});
      }
    })();
  }, [node.node_hash]);
  return <dialog ref={ref} onClose={onClose} onCancel={onClose} aria-labelledby="node-title">
    <h2 id="node-title">Audit node {node.index}</h2>
    <dl>
      <dt>Timestamp</dt><dd>{exactTime(node.timestamp)}</dd>
      <dt>State ID</dt><dd className="hash">{node.state_id}</dd>
      <dt>Node hash</dt><dd className="hash">{node.node_hash}</dd>
      <dt>DAG-CBOR CIDv1</dt><dd className="cid">{node.cid}</dd>
      <dt>Merkle root</dt><dd className="hash">{node.merkle_root}</dd>
      <dt>Tenant</dt><dd>{node.tenant_id}</dd>
      <dt>Model / endpoint</dt><dd>{node.model} / {node.endpoint}</dd>
      <dt>Tokens / latency</dt><dd>{node.token_count} / {node.latency_ms === null ? "not recorded" : `${node.latency_ms.toFixed(3)} ms`}</dd>
      <dt>Terminal outcome</dt><dd>{node.terminal_outcome ?? "not a terminal stream record"}</dd>
      <dt>Signature</dt><dd>{node.signature_scheme}; {node.signature_status}</dd>
      <dt>PHI scrubbed</dt><dd>{node.phi_scrubbed ? "Yes" : "No"}</dd>
    </dl>
    <h3>Canonical raw evidence</h3>
    {evidence.kind === "loading" && <p aria-live="polite">Loading canonical evidence…</p>}
    {evidence.kind === "error" && <p role="alert">{evidence.message}</p>}
    {evidence.kind === "ready" && <>
      <h4>RFC 8785 JCS projection</h4><pre className="raw-block">{evidence.data.jcs_json}</pre>
      <h4>RFC 8949 deterministic DAG-CBOR (base64)</h4><pre className="raw-block">{evidence.data.dag_cbor_base64}</pre>
      <p>SHA-256: <span className="hash">{evidence.data.dag_cbor_sha256}</span></p>
    </>}
    <button onClick={() => ref.current?.close()}>Close</button>
  </dialog>;
}

export function LedgerTable({nodes}: Readonly<{nodes: readonly AuditNode[]}>) {
  const [paged, setPaged] = useState(false);
  const [selected, setSelected] = useState<AuditNode | null>(null);
  const parentRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({count: nodes.length, getScrollElement: () => parentRef.current, estimateSize: () => 72, overscan: 8});
  if (!nodes.length) return <section className="notice"><h2>No audit nodes</h2><p>The endpoint returned an empty retained window. No rows are synthesized.</p></section>;
  return <>
    <label><input type="checkbox" checked={paged} onChange={(event) => setPaged(event.target.checked)} style={{width: "auto", minHeight: "auto"}}/> Use accessible paged table (disables virtualization)</label>
    {paged ? <div className="table-wrap"><table className="data-table"><caption>Current retained audit-node page</caption><thead><tr><th>Index</th><th>Timestamp (UTC)</th><th>CIDv1</th><th>Tenant</th><th>Model / provider</th><th>Tokens</th><th>Latency</th><th>Policy</th><th>Details</th></tr></thead><tbody>{nodes.map((node) => <tr key={node.node_hash}><td>{node.index}</td><td><time dateTime={exactTime(node.timestamp)}>{exactTime(node.timestamp)}</time></td><td><ShortValue value={node.cid} className="cid"/></td><td>{node.tenant_id}</td><td>{node.model}<br/><small>{node.endpoint}</small></td><td>{node.token_count}</td><td>{node.latency_ms === null ? "N/A" : `${node.latency_ms.toFixed(3)} ms`}</td><td>{node.phi_scrubbed ? "PII/PHI redacted" : node.terminal_outcome ?? "none recorded"}</td><td><button onClick={() => setSelected(node)} aria-label={`Inspect audit node ${node.index}`}>Inspect</button></td></tr>)}</tbody></table></div>
      : <div ref={parentRef} className="virtual-table" role="table" aria-label="Virtualized audit-node page"><div className="virtual-head" role="row"><span role="columnheader">Index</span><span role="columnheader">Timestamp</span><span role="columnheader">CIDv1</span><span role="columnheader" className="optional-col">Tenant</span><span role="columnheader" className="optional-col">Model</span><span role="columnheader">Tokens</span><span role="columnheader">Details</span></div><div role="rowgroup" style={{height: virtualizer.getTotalSize(), position: "relative"}}>{virtualizer.getVirtualItems().map((item) => { const node = nodes[item.index]; return node ? <div className="virtual-row" role="row" key={node.node_hash} style={{height: item.size, transform: `translateY(${item.start}px)`}}><Cells node={node} onSelect={setSelected}/></div> : null; })}</div></div>}
    {selected && <NodeDialog node={selected} onClose={() => setSelected(null)}/>} 
  </>;
}
