import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

import {
  AegisProofError,
  parseInclusionProof,
  verifyInclusion,
  verifyProofHeaders,
} from "../src/index.js";

interface VectorCase {
  readonly leaf_count: number;
  readonly leaves_hex: readonly string[];
  readonly proofs: readonly unknown[];
  readonly root: string;
}

const vectors = JSON.parse(
  readFileSync(new URL("../../shared/mmr-inclusion-v1.json", import.meta.url), "utf8"),
) as { readonly cases: readonly VectorCase[] };
const subtle = webcrypto.subtle as unknown as SubtleCrypto;
const hexBytes = (value: string): Uint8Array => Uint8Array.from(
  value.match(/.{2}/g)?.map((part) => Number.parseInt(part, 16)) ?? [],
);
const base64url = (value: Uint8Array): string => Buffer.from(value).toString("base64url");

describe("aegis-mmr-inclusion-v1", () => {
  test("verifies every shared vector without local MMR state", async () => {
    for (const vector of vectors.cases) {
      expect(vector.proofs).toHaveLength(vector.leaf_count);
      for (let index = 0; index < vector.leaf_count; index += 1) {
        const proof = parseInclusionProof(vector.proofs[index]);
        const leafHex = vector.leaves_hex[index];
        expect(leafHex).toBeDefined();
        expect(await verifyInclusion(hexBytes(leafHex ?? ""), proof, vector.root, subtle)).toBe(true);
      }
    }
  });

  test("rejects tampered position, leaf, root and unknown fields", async () => {
    const vector = vectors.cases[4];
    expect(vector).toBeDefined();
    if (vector === undefined) return;
    const raw = vector.proofs[2];
    const proof = parseInclusionProof(raw);
    expect(await verifyInclusion(new TextEncoder().encode("tampered"), proof, vector.root, subtle)).toBe(false);
    expect(await verifyInclusion(hexBytes(vector.leaves_hex[2] ?? ""), { ...proof, leaf_index: 3 }, vector.root, subtle)).toBe(false);
    expect(await verifyInclusion(hexBytes(vector.leaves_hex[2] ?? ""), proof, "0".repeat(64), subtle)).toBe(false);
    expect(() => parseInclusionProof({ ...(raw as object), extra: true })).toThrow(AegisProofError);
  });

  test("parses and verifies response headers", async () => {
    const vector = vectors.cases[2];
    expect(vector).toBeDefined();
    if (vector === undefined) return;
    const proof = vector.proofs[2];
    const leaf = hexBytes(vector.leaves_hex[2] ?? "");
    const leafHash = Buffer.from(await subtle.digest("SHA-256", leaf)).toString("hex");
    const headers = new Headers({
      "X-Aegis-MMR-Leaf": leafHash,
      "X-Aegis-MMR-Proof": base64url(new TextEncoder().encode(JSON.stringify(proof))),
      "X-Aegis-MMR-Root": vector.root,
    });
    expect((await verifyProofHeaders(headers, vector.root, subtle)).leaf_index).toBe(2);
    await expect(verifyProofHeaders(headers, "0".repeat(64), subtle)).rejects.toThrow(AegisProofError);
  });
});
