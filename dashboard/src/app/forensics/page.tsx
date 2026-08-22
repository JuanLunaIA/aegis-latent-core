import { ForensicExport } from "@/components/ForensicExport";

export default function ForensicsPage() {
  return <>
    <h1>Forensic bundle export</h1>
    <p className="lede">Acquire a bounded retained-window slice with canonical manifest, DAG-CBOR ledger records, portable MMR proofs, a technical PDF certificate, and offline SHA-256 verification.</p>
    <ForensicExport/>
  </>;
}
