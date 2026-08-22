import { NextRequest, NextResponse } from "next/server";

import { aegisFetch, boundedText, publicError } from "@/lib/aegis-client.server";
import { proofSchema } from "@/lib/contracts";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const stateId = request.nextUrl.searchParams.get("state_id")?.trim();
  if (!stateId || stateId.length > 256 || /[\u0000-\u001f]/.test(stateId)) {
    return NextResponse.json({error: "A valid state identifier is required."}, {status: 400});
  }
  try {
    const response = await aegisFetch(`/v1/audit/proofs/${encodeURIComponent(stateId)}`);
    if (response.status === 404) return NextResponse.json({error: "No proof was found."}, {status: 404});
    if (response.status === 409) return NextResponse.json({error: "This legacy record has no portable proof."}, {status: 409});
    if (!response.ok) throw new Error(`upstream ${response.status}`);
    return NextResponse.json(proofSchema.parse(JSON.parse(await boundedText(response))), {headers: {"Cache-Control": "no-store"}});
  } catch (error) {
    return NextResponse.json(publicError(error), {status: 502});
  }
}
