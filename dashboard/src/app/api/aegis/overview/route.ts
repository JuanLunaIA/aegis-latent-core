import { NextResponse } from "next/server";

import { aegisFetch, boundedText, publicError } from "@/lib/aegis-client.server";
import { auditHealthSchema, integritySchema, serviceHealthSchema } from "@/lib/contracts";

export const dynamic = "force-dynamic";

async function json(path: string): Promise<unknown> {
  const response = await aegisFetch(path);
  if (!response.ok) throw new Error(`upstream ${response.status}`);
  return JSON.parse(await boundedText(response));
}

export async function GET() {
  try {
    const [health, ready, audit, integrity] = await Promise.all([
      json("/health"), json("/ready"), json("/v1/audit/health"), json("/v1/audit/integrity"),
    ]);
    return NextResponse.json({
      health: serviceHealthSchema.parse(health), ready: serviceHealthSchema.parse(ready),
      audit: auditHealthSchema.parse(audit), integrity: integritySchema.parse(integrity),
      fetched_at: new Date().toISOString(),
    }, {headers: {"Cache-Control": "no-store"}});
  } catch (error) {
    return NextResponse.json(publicError(error), {status: 502});
  }
}
