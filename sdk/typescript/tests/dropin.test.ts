import OfficialAnthropic from "@anthropic-ai/sdk";
import OfficialOpenAI from "openai";
import { describe, expect, test } from "vitest";

import { Anthropic } from "../src/anthropic.js";
import { OpenAI } from "../src/openai.js";
import type { AegisFetch } from "../src/types.js";

function response(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "X-Aegis-Evidence-Status": "pending-terminal",
    },
  });
}

describe("provider-native drop-in clients", () => {
  test("OpenAI preserves native chat completion execution and injects identity", async () => {
    let observed: Request | undefined;
    const mockFetch: AegisFetch = async (input, init) => {
      observed = new Request(input, init);
      return response({
        id: "chatcmpl-aegis",
        object: "chat.completion",
        created: 1,
        model: "gpt-test",
        choices: [{ index: 0, finish_reason: "stop", message: { role: "assistant", content: "ok" } }],
        usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
      });
    };
    const client = new OpenAI({
      aegisApiKey: "gateway-secret",
      gatewayUrl: "https://gateway.test",
      tenantId: "tenant-a",
      sessionId: "session-a",
      traceContext: "00-00000000000000000000000000000000-0000000000000000-01",
      fetch: mockFetch,
      maxRetries: 0,
    });
    expect(client).toBeInstanceOf(OfficialOpenAI);
    const result = await client.chat.completions.create({
      model: "gpt-test",
      messages: [{ role: "user", content: "hello" }],
    });
    expect(result.choices[0]?.message.content).toBe("ok");
    expect(observed?.url).toBe("https://gateway.test/v1/chat/completions");
    expect(observed?.headers.get("X-Aegis-Tenant-ID")).toBe("tenant-a");
    expect(observed?.headers.get("X-Aegis-Session-ID")).toBe("session-a");
  });

  test("Anthropic preserves native messages execution and identity headers", async () => {
    let observed: Request | undefined;
    const mockFetch: AegisFetch = async (input, init) => {
      observed = new Request(input, init);
      return response({
        id: "msg_aegis",
        type: "message",
        role: "assistant",
        model: "claude-test",
        content: [{ type: "text", text: "ok", citations: null }],
        stop_reason: "end_turn",
        stop_sequence: null,
        usage: { input_tokens: 1, output_tokens: 1 },
      });
    };
    const client = new Anthropic({
      aegisApiKey: "gateway-secret",
      gatewayUrl: "https://gateway.test",
      tenantId: "tenant-a",
      sessionId: "session-a",
      fetch: mockFetch,
      maxRetries: 0,
    });
    expect(client).toBeInstanceOf(OfficialAnthropic);
    const result = await client.messages.create({
      model: "claude-test",
      max_tokens: 16,
      messages: [{ role: "user", content: "hello" }],
    });
    expect(result.content[0]?.type).toBe("text");
    expect(observed?.url).toBe("https://gateway.test/v1/messages");
    expect(observed?.headers.get("X-Aegis-Tenant-ID")).toBe("tenant-a");
    expect(observed?.headers.get("X-Aegis-Session-ID")).toBe("session-a");
  });

  test("proof mode fails closed without an independently trusted root", () => {
    expect(() => new OpenAI({
      aegisApiKey: "gateway-secret",
      gatewayUrl: "https://gateway.test",
      tenantId: "tenant-a",
      verifyProof: true,
    })).toThrow(/trustedMmrRoot/);
  });
});
