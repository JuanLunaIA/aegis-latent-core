import "server-only";

const MAX_BYTES = 2 * 1024 * 1024;
const MAX_EXPORT_BYTES = 64 * 1024 * 1024;

interface AegisFetchOptions {
  readonly body?: string;
  readonly method?: "GET" | "POST";
  readonly contentType?: string;
  readonly exportResponse?: boolean;
}

function baseUrl(): URL {
  const raw = process.env.AEGIS_PRIMARY_BASE_URL;
  if (!raw) throw new Error("dashboard backend is not configured");
  const parsed = new URL(raw);
  if (!(["http:", "https:"] as const).includes(parsed.protocol as "http:" | "https:")) {
    throw new Error("dashboard backend URL must be HTTP(S)");
  }
  if (parsed.username || parsed.password) throw new Error("backend URL must not contain credentials");
  return parsed;
}

export async function aegisFetch(path: string, options: AegisFetchOptions = {}): Promise<Response> {
  if (!path.startsWith("/")) throw new Error("backend path must be absolute");
  const token = process.env.AEGIS_DASHBOARD_API_KEY;
  if (!token) throw new Error("dashboard API key is not configured");
  const response = await fetch(new URL(path, baseUrl()), {
    method: options.method ?? "GET",
    headers: {
      Authorization: `Bearer ${token}`,
      ...(options.contentType === undefined ? {} : {"Content-Type": options.contentType}),
    },
    ...(options.body === undefined ? {} : {body: options.body}),
    cache: "no-store",
    signal: AbortSignal.timeout(options.exportResponse ? 60_000 : 5_000),
  });
  const length = Number(response.headers.get("content-length") ?? "0");
  const maxBytes = options.exportResponse ? MAX_EXPORT_BYTES : MAX_BYTES;
  if (Number.isFinite(length) && length > maxBytes) throw new Error("backend response exceeds limit");
  return response;
}

export async function boundedText(response: Response): Promise<string> {
  const text = await response.text();
  if (new TextEncoder().encode(text).byteLength > MAX_BYTES) throw new Error("backend response exceeds limit");
  return text;
}

export function publicError(error: unknown): {error: string} {
  if (error instanceof Error && error.message.includes("not configured")) return {error: "Dashboard backend is not configured."};
  return {error: "The Aegis backend request failed."};
}
