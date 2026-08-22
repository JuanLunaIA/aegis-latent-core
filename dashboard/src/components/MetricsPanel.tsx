"use client";

import { useEffect, useRef, useState } from "react";
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

interface Sample {readonly name: string; readonly labels: string; readonly value: number}
interface Point {readonly time: string; readonly tokensPerSecond: number | null; readonly redactions: number | null}
type State =
  | {readonly kind: "loading"}
  | {readonly kind: "error"; readonly message: string}
  | {readonly kind: "ready"; readonly sourceState: string; readonly samples: Sample[]; readonly scrapedAt?: string};

function total(samples: readonly Sample[], name: string): number | null {
  const matches = samples.filter((sample) => sample.name === name);
  return matches.length ? matches.reduce((sum, sample) => sum + sample.value, 0) : null;
}

function histogramQuantile(samples: readonly Sample[], quantile: number): number | null {
  const buckets = new Map<number, number>();
  for (const sample of samples) {
    if (sample.name !== "aegis_stream_duration_seconds_bucket") continue;
    const raw = /(?:^|[,{}])le="([^"]+)"/.exec(sample.labels)?.[1];
    if (raw === undefined || raw === "+Inf") continue;
    const upper = Number(raw);
    if (Number.isFinite(upper)) buckets.set(upper, (buckets.get(upper) ?? 0) + sample.value);
  }
  const ordered = [...buckets.entries()].sort(([left], [right]) => left - right);
  if (!ordered.length) return null;
  const count = ordered.at(-1)?.[1] ?? 0;
  if (count <= 0) return null;
  const target = count * quantile;
  let previousUpper = 0;
  let previousCount = 0;
  for (const [upper, cumulative] of ordered) {
    if (cumulative >= target) {
      const inBucket = cumulative - previousCount;
      const fraction = inBucket <= 0 ? 0 : (target - previousCount) / inBucket;
      return previousUpper + (upper - previousUpper) * fraction;
    }
    previousUpper = upper;
    previousCount = cumulative;
  }
  return ordered.at(-1)?.[0] ?? null;
}

function value(value: number | null, suffix = ""): string {
  return value === null ? "Unavailable" : `${value.toFixed(3)}${suffix}`;
}

export function MetricsPanel() {
  const [state, setState] = useState<State>({kind: "loading"});
  const [points, setPoints] = useState<Point[]>([]);
  const previous = useRef<{tokens: number; time: number} | null>(null);

  async function load(initial = false): Promise<void> {
    if (initial) setState({kind: "loading"});
    try {
      const response = await fetch("/api/aegis/metrics", {cache: "no-store"});
      const payload = await response.json() as {state?: string; samples?: Sample[]; scraped_at?: string; error?: string};
      if (!response.ok) throw new Error(payload.error ?? "Metrics unavailable");
      const samples = payload.samples ?? [];
      const scrapedAt = payload.scraped_at;
      setState({kind: "ready", sourceState: payload.state ?? "empty", samples, ...(scrapedAt ? {scrapedAt} : {})});
      const tokenCount = total(samples, "aegis_stream_tokens_total");
      const redactions = total(samples, "aegis_stream_redactions_total");
      const now = scrapedAt ? new Date(scrapedAt).valueOf() : Date.now();
      let rate: number | null = null;
      if (tokenCount !== null && previous.current !== null && now > previous.current.time && tokenCount >= previous.current.tokens) {
        rate = (tokenCount - previous.current.tokens) / ((now - previous.current.time) / 1000);
      }
      if (tokenCount !== null) previous.current = {tokens: tokenCount, time: now};
      setPoints((current) => [...current, {time: new Date(now).toISOString(), tokensPerSecond: rate, redactions}].slice(-120));
    } catch (error: unknown) {
      setState({kind: "error", message: error instanceof Error ? error.message : "Metrics unavailable"});
    }
  }

  useEffect(() => {
    void load(true);
    const timer = window.setInterval(() => void load(false), 5_000);
    return () => window.clearInterval(timer);
  }, []);

  if (state.kind === "loading") return <p aria-live="polite">Loading current Prometheus samples…</p>;
  if (state.kind === "error") return <section className="notice error" role="alert"><h2>Metrics error</h2><p>{state.message}</p><button onClick={() => void load(true)}>Retry</button></section>;
  if (state.sourceState === "unavailable") return <section className="notice"><h2>Telemetry unavailable</h2><p>The configured gateway does not expose the optional metrics endpoint.</p></section>;
  if (!state.samples.length) return <section className="notice"><h2>No samples observed</h2><p>The scrape was reachable but returned no allowlisted Aegis series. This is not interpreted as zero.</p></section>;

  const p50 = histogramQuantile(state.samples, 0.50);
  const p95 = histogramQuantile(state.samples, 0.95);
  const p99 = histogramQuantile(state.samples, 0.99);
  const latestRate = points.at(-1)?.tokensPerSecond ?? null;
  const redactions = total(state.samples, "aegis_stream_redactions_total");
  return <>
    <p className="notice">Five-second Prometheus scrapes from the configured gateway. Quantiles are estimated from cumulative histogram buckets; token rate requires two consecutive counter samples. Missing series remain unavailable, never zero-filled.</p>
    <div className="kpis">
      <div className="kpi"><span>Stream p50</span><strong>{value(p50, " s")}</strong></div>
      <div className="kpi"><span>Stream p95</span><strong>{value(p95, " s")}</strong></div>
      <div className="kpi"><span>Stream p99</span><strong>{value(p99, " s")}</strong></div>
      <div className="kpi"><span>Tokens / second</span><strong>{value(latestRate)}</strong></div>
      <div className="kpi"><span>Total redactions</span><strong>{redactions === null ? "Unavailable" : redactions.toLocaleString()}</strong></div>
      <div className="kpi"><span>Formal invariant status</span><strong>Unavailable</strong><small>No runtime verifier series is exposed.</small></div>
    </div>
    <div className="chart" aria-label="Time series of observed tokens per second and cumulative redactions"><ResponsiveContainer width="100%" height="100%"><LineChart data={points} margin={{left: 16, right: 16, bottom: 50}}><CartesianGrid strokeDasharray="3 3"/><XAxis dataKey="time" tickFormatter={(time: string) => new Date(time).toLocaleTimeString()} angle={-25} textAnchor="end" height={70}/><YAxis/><Tooltip/><Legend/><Line connectNulls={false} type="monotone" dataKey="tokensPerSecond" name="tokens/s" stroke="#61dafb" dot={false}/><Line type="monotone" dataKey="redactions" name="cumulative redactions" stroke="#b0ffb0" dot={false}/></LineChart></ResponsiveContainer></div>
    <div className="table-wrap"><table className="data-table"><caption>Exact current Prometheus samples</caption><thead><tr><th>Series</th><th>Labels</th><th>Value</th></tr></thead><tbody>{state.samples.map((sample, index) => <tr key={`${sample.name}-${sample.labels}-${index}`}><td className="hash">{sample.name}</td><td className="hash">{sample.labels || "none"}</td><td>{sample.value}</td></tr>)}</tbody></table></div>
    {state.scrapedAt && <p className="muted">Scraped at <time dateTime={state.scrapedAt}>{new Date(state.scrapedAt).toLocaleString()}</time></p>}
  </>;
}
