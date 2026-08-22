import { type NextRequest, NextResponse } from "next/server";

import { aegisFetch, boundedText, publicError } from "@/lib/aegis-client.server";
import { nodesSchema } from "@/lib/contracts";

export const dynamic = "force-dynamic";

const TEXT_FILTERS = ["tenant_id", "model", "endpoint", "terminal_outcome"] as const;

export async function GET(request: NextRequest): Promise<Response> {
  const rawOffset = Number(request.nextUrl.searchParams.get("offset") ?? "0");
  const rawLimit = Number(request.nextUrl.searchParams.get("limit") ?? "100");
  if (!Number.isInteger(rawOffset) || rawOffset < 0 || !Number.isInteger(rawLimit) || rawLimit < 1 || rawLimit > 1000) {
    return NextResponse.json({error: "Invalid pagination parameters."}, {status: 400});
  }
  const params = new URLSearchParams({offset: String(rawOffset), limit: String(rawLimit)});
  for (const name of TEXT_FILTERS) {
    const value = request.nextUrl.searchParams.get(name)?.trim();
    if (value) params.set(name, value.slice(0, 256));
  }
  for (const name of ["phi_scrubbed", "failures_only"] as const) {
    const value = request.nextUrl.searchParams.get(name);
    if (value === "true" || value === "false") params.set(name, value);
  }
  const latency = request.nextUrl.searchParams.get("min_latency_ms");
  if (latency !== null) {
    const value = Number(latency);
    if (!Number.isFinite(value) || value < 0) {
      return NextResponse.json({error: "Invalid latency threshold."}, {status: 400});
    }
    params.set("min_latency_ms", String(value));
  }
  try {
    const response = await aegisFetch(`/v1/audit/nodes?${params}`);
    if (!response.ok) throw new Error(`upstream ${response.status}`);
    const nodes = nodesSchema.parse(JSON.parse(await boundedText(response)));
    return NextResponse.json(
      {nodes, offset: rawOffset, limit: rawLimit, returned: nodes.length},
      {headers: {"Cache-Control": "no-store"}},
    );
  } catch (error: unknown) {
    return NextResponse.json(publicError(error), {status: 502});
  }
}
