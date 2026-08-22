// Copyright (c) 2026 Juan Luna. All rights reserved.
export interface AegisGatewayConfig {
  readonly aegisApiKey: string;
  readonly gatewayUrl: string;
  readonly tenantId: string;
  readonly sessionId?: string;
  readonly traceContext?: string;
  readonly defaultHeaders?: Readonly<Record<string, string>>;
}

export interface OpenAIGatewayOptions {
  readonly apiKey: string;
  readonly baseURL: string;
  readonly defaultHeaders: Readonly<Record<string, string>>;
}

export interface AnthropicGatewayOptions {
  readonly authToken: string;
  readonly baseURL: string;
  readonly defaultHeaders: Readonly<Record<string, string>>;
}

function normalizeGatewayUrl(value: string, openAI: boolean): string {
  let parsed: URL;
  try {
    parsed = new URL(value.trim());
  } catch {
    throw new TypeError("gatewayUrl must be an absolute HTTP(S) URL");
  }
  if (!(["http:", "https:"] as const).includes(parsed.protocol as "http:" | "https:")) {
    throw new TypeError("gatewayUrl must be an absolute HTTP(S) URL");
  }
  if (parsed.username || parsed.password) {
    throw new TypeError("gatewayUrl must not contain credentials");
  }
  parsed.search = "";
  parsed.hash = "";
  let path = parsed.pathname.replace(/\/+$/, "");
  if (openAI && !path.endsWith("/v1")) path += "/v1";
  parsed.pathname = `${path}/`;
  return parsed.toString();
}

function gatewayHeaders(config: AegisGatewayConfig): Readonly<Record<string, string>> {
  if (!config.tenantId.trim()) throw new TypeError("tenantId must not be empty");
  const sessionId = config.sessionId ?? globalThis.crypto.randomUUID();
  if (!sessionId.trim()) throw new TypeError("sessionId must not be empty");
  const traceContext = config.traceContext
    ?? `00-${globalThis.crypto.randomUUID().replaceAll("-", "")}-${globalThis.crypto.randomUUID().replaceAll("-", "").slice(0, 16)}-01`;
  return {
    ...(config.defaultHeaders ?? {}),
    "X-Aegis-Tenant-ID": config.tenantId,
    "X-Aegis-Session-ID": sessionId,
    "X-Aegis-Trace-Context": traceContext,
  };
}

export function openAIGatewayOptions(config: AegisGatewayConfig): OpenAIGatewayOptions {
  if (!config.aegisApiKey) throw new TypeError("aegisApiKey must not be empty");
  return {
    apiKey: config.aegisApiKey,
    baseURL: normalizeGatewayUrl(config.gatewayUrl, true),
    defaultHeaders: gatewayHeaders(config),
  };
}

export function anthropicGatewayOptions(config: AegisGatewayConfig): AnthropicGatewayOptions {
  if (!config.aegisApiKey) throw new TypeError("aegisApiKey must not be empty");
  return {
    authToken: config.aegisApiKey,
    baseURL: normalizeGatewayUrl(config.gatewayUrl, false),
    defaultHeaders: gatewayHeaders(config),
  };
}
