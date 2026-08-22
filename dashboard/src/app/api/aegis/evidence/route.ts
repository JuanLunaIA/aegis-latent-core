import { type NextRequest, NextResponse } from "next/server";

import { aegisFetch, boundedText, publicError } from "@/lib/aegis-client.server";
import { rawEvidenceSchema } from "@/lib/contracts";

export const dynamic = "force-dynamic";

const HASH = /^[0-9a-f]{64}$/;

export async function GET(request: NextRequest): Promise<Response> {
  const nodeHash = request.nextUrl.searchParams.get("node_hash") ?? "";
  if (!HASH.test(nodeHash)) {
    return NextResponse.json({error: "node_hash must be a lowercase SHA-256 digest."}, {status: 400});
  }
  try {
    const response = await aegisFetch(`/v1/audit/nodes/${nodeHash}/evidence`);
    const text = await boundedText(response);
    if (!response.ok) return new Response(text, {status: response.status});
    const value = rawEvidenceSchema.parse(JSON.parse(text));
    return NextResponse.json(value, {headers: {"Cache-Control": "no-store"}});
  } catch (error: unknown) {
    return NextResponse.json(publicError(error), {status: 502});
  }
}
