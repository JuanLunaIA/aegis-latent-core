import { OverviewPanel } from "@/components/OverviewPanel";

export default function OverviewPage() {
  return <><h1>Operational overview</h1><p className="lede">Current gateway, retained-window integrity, and evidence subsystem state. Values are fetched from the configured Aegis deployment.</p><OverviewPanel/></>;
}
