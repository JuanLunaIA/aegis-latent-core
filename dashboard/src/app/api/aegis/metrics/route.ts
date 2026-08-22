import { NextResponse } from "next/server";

import { aegisFetch, boundedText, publicError } from "@/lib/aegis-client.server";
import { parsePrometheus } from "@/lib/prometheus";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const response = await aegisFetch("/metrics");
    if (response.status === 404) return NextResponse.json({state: "unavailable", samples: []});
    if (!response.ok) throw new Error(`upstream ${response.status}`);
    const samples = parsePrometheus(await boundedText(response));
    return NextResponse.json({state: samples.length ? "live" : "empty", samples, scraped_at: new Date().toISOString()}, {headers: {"Cache-Control": "no-store"}});
  } catch (error) {
    return NextResponse.json({...publicError(error), state: "error", samples: []}, {status: 502});
  }
}
