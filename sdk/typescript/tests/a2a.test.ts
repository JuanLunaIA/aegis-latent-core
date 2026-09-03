// Copyright (c) 2026 Juan Luna. All rights reserved.
//
// Cross-implementation agreement for the A2A receipt verifier.
//
// The verifier here reimplements the canonical envelope and the MMR leaf that
// `aegis/core/a2a.py` commits. Two independent implementations of one hashed
// byte layout is exactly the kind of thing that drifts silently, and the
// failure is total rather than partial: a verifier that disagrees by one byte
// rejects every valid receipt.
//
// The fixture below was issued by the Python implementation against a real
// ledger — five leaves, the receipt at index 4 — and is pinned so this test
// fails if either side's byte layout changes.

import { describe, expect, it } from "vitest";

import { a2aLeafHash, parseAgentReceipt, verifyReceipt } from "../src/a2a.js";

const FIXTURE = {
    "receipt": {
      "caller_agent_id": "planner",
      "execution_id": "a2a-36e666eba6a421d823141ee66d164563",
      "inclusion_proof": {
        "algorithm": "sha256-asciihex",
        "leaf_count": 5,
        "leaf_index": 4,
        "path": [],
        "peak_index": 1,
        "peaks": [
          {
            "hash": "a04fde22a6e231f50dbc09d996cd45146935934f23c2c414f3127ce6079eb3ad",
            "height": 2
          },
          {
            "hash": "32b590a77e45b855af35b32188b5e981548751b260f5dc496f66b37803c88fb6",
            "height": 0
          }
        ],
        "root": "ec4af1bfe5fd7c4a38a1049631d384aa70209091dd98225123af8e7f3814e80e",
        "version": "aegis-mmr-inclusion-v1"
      },
      "input_hash": "85a904ca800e5db106f7bf4992c1caf73c29a42beee73c90d6a32a5f32237cdf",
      "mmr_root": "ec4af1bfe5fd7c4a38a1049631d384aa70209091dd98225123af8e7f3814e80e",
      "output_hash": "65c0fd1a2a6400fe80ca8c0e48667ecabc16b4c9a30b47376ff1518e7236406f",
      "target_agent_id": "research",
      "timestamp": 1788456000.5,
      "tool_name": "web.query",
      "version": "aegis-a2a-receipt-v1"
    },
    "root": "ec4af1bfe5fd7c4a38a1049631d384aa70209091dd98225123af8e7f3814e80e"
  } as const;

const RECEIPT = FIXTURE.receipt as unknown as Parameters<typeof verifyReceipt>[0];
const ROOT = FIXTURE.root;

describe("A2A receipts", () => {
  it("verifies a receipt issued by the Python implementation", async () => {
    await expect(verifyReceipt(RECEIPT, ROOT)).resolves.toBe(true);
  });

  it("derives a leaf hash from the receipt's own fields", async () => {
    const hash = await a2aLeafHash(parseAgentReceipt(RECEIPT));
    expect(hash).toMatch(/^[0-9a-f]{64}$/u);
  });

  it("rejects a receipt whose bound fields were altered", async () => {
    for (const [field, value] of [
      ["tool_name", "web.delete"],
      ["caller_agent_id", "admin"],
      ["target_agent_id", "billing"],
      ["execution_id", "someone-elses-run"],
      ["input_hash", "0".repeat(64)],
      ["output_hash", "f".repeat(64)],
    ] as const) {
      const tampered = { ...(RECEIPT as object), [field]: value };
      await expect(verifyReceipt(tampered, ROOT)).resolves.toBe(false);
    }
  });

  it("rejects an altered timestamp", async () => {
    const receipt = RECEIPT as unknown as { timestamp: number };
    const tampered = { ...(RECEIPT as object), timestamp: receipt.timestamp + 1 };
    await expect(verifyReceipt(tampered, ROOT)).resolves.toBe(false);
  });

  it("rejects a root it was not issued against", async () => {
    await expect(verifyReceipt(RECEIPT, "a".repeat(64))).resolves.toBe(false);
    await expect(verifyReceipt(RECEIPT, "not-a-root")).resolves.toBe(false);
  });

  it("rejects an unknown version", async () => {
    const tampered = { ...(RECEIPT as object), version: "aegis-a2a-receipt-v2" };
    await expect(verifyReceipt(tampered, ROOT)).resolves.toBe(false);
  });

  it("refuses a missing field rather than defaulting it", async () => {
    const { tool_name: _omitted, ...partial } = RECEIPT as unknown as Record<string, unknown>;
    await expect(verifyReceipt(partial, ROOT)).resolves.toBe(false);
  });

  it("resolves false rather than throwing on junk", async () => {
    for (const junk of [null, 42, "receipt", {}, { version: 1 }]) {
      await expect(verifyReceipt(junk, ROOT)).resolves.toBe(false);
    }
  });
});
