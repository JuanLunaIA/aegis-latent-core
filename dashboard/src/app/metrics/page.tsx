import { MetricsPanel } from "@/components/MetricsPanel";

export default function MetricsPage(){return <><h1>Current telemetry</h1><p className="lede">Allowlisted values parsed server-side from the configured gateway's current Prometheus exposition.</p><MetricsPanel/></>;}
