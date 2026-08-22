import { type NextRequest, NextResponse } from "next/server";

import { aegisFetch, boundedText, publicError } from "@/lib/aegis-client.server";

export const dynamic = "force-dynamic";

const MAX_REQUEST_BYTES = 16 * 1024;

export async function POST(request: NextRequest): Promise<Response> {
  const origin = request.headers.get("origin");
  if (origin !== null && origin !== request.nextUrl.origin) {
    return NextResponse.json({error: "Cross-origin export requests are rejected."}, {status: 403});
  }
  try {
    const body = await request.text();
    if (new TextEncoder().encode(body).byteLength > MAX_REQUEST_BYTES) {
      return NextResponse.json({error: "Export request exceeds the allowed size."}, {status: 413});
    }
    JSON.parse(body);
    const upstream = await aegisFetch("/v1/audit/forensics/export", {
      method: "POST",
      contentType: "application/json",
      body,
      exportResponse: true,
    });
    if (!upstream.ok) {
      const detail = await boundedText(upstream);
      return new Response(detail, {
        status: upstream.status,
        headers: {"Content-Type": upstream.headers.get("content-type") ?? "application/json"},
      });
    }
    return new Response(upstream.body, {
      status: upstream.status,
      headers: {
        "Cache-Control": "no-store",
        "Content-Type": "application/zip",
        "Content-Disposition": upstream.headers.get("content-disposition")
          ?? 'attachment; filename="aegis-forensic.zip"',
        "X-Content-Type-Options": "nosniff",
      },
    });
  } catch (error: unknown) {
    return NextResponse.json(publicError(error), {status: 502});
  }
}
