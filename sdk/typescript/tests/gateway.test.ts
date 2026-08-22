import { describe, expect, test } from "vitest";

import { anthropicGatewayOptions, openAIGatewayOptions } from "../src/gateway.js";

describe("official provider constructor options", () => {
  test("OpenAI options preserve required Aegis identity headers", () => {
    const options = openAIGatewayOptions({
      aegisApiKey: "proxy-secret",
      gatewayUrl: "https://gateway.test/control",
      tenantId: "tenant-a",
      sessionId: "session-a",
      traceContext: "00-00000000000000000000000000000000-0000000000000000-01",
    });
    expect(options.apiKey).toBe("proxy-secret");
    expect(options.baseURL).toBe("https://gateway.test/control/v1/");
    expect(options.defaultHeaders["X-Aegis-Tenant-ID"]).toBe("tenant-a");
    expect(options.defaultHeaders["X-Aegis-Session-ID"]).toBe("session-a");
  });

  test("Anthropic options select bearer authToken and native base URL", () => {
    const options = anthropicGatewayOptions({
      aegisApiKey: "proxy-secret",
      gatewayUrl: "https://gateway.test",
      tenantId: "tenant-a",
      sessionId: "session-a",
    });
    expect(options.authToken).toBe("proxy-secret");
    expect(options.baseURL).toBe("https://gateway.test/");
  });

  test("embedded credentials and empty tenant fail closed", () => {
    expect(() => openAIGatewayOptions({
      aegisApiKey: "secret",
      gatewayUrl: "https://user:pass@gateway.test",
      tenantId: "tenant-a",
    })).toThrow(/credentials/);
    expect(() => anthropicGatewayOptions({
      aegisApiKey: "secret",
      gatewayUrl: "https://gateway.test",
      tenantId: " ",
    })).toThrow(/tenantId/);
  });
});
