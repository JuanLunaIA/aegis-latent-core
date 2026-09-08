// Copyright (c) 2026 Juan Luna. All rights reserved.
// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
//
// The v2 MMR is domain-separated: leaf = SHA-256(0x00 || payload), node =
// SHA-256(0x01 || left32 || right32), root = SHA-256(0x02 || peaks). This file
// is pinned against a fixture the *Python* implementation issued, because two
// hand-written canonicalisations of one hashed byte layout drift silently and
// the resulting failure is total rather than partial — the same reason the A2A
// port carries a pinned fixture.
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseInclusionProof, verifyInclusion } from "../src/proof.js";

const fixture = JSON.parse(
  readFileSync(fileURLToPath(new URL("./fixtures/mmr_v2_python_issued.json", import.meta.url)), "utf8"),
) as { leaves: string[]; root: string; proofs: unknown[] };

const encoder = new TextEncoder();

describe("aegis-mmr-inclusion-v2", () => {
  it("verifies every Python-issued proof", async () => {
    for (let index = 0; index < fixture.leaves.length; index += 1) {
      const proof = parseInclusionProof(fixture.proofs[index]);
      expect(proof.version).toBe("aegis-mmr-inclusion-v2");
      expect(proof.algorithm).toBe("sha256-binary-domain-separated");
      const leaf = encoder.encode(fixture.leaves[index]!);
      expect(await verifyInclusion(leaf, proof, fixture.root)).toBe(true);
    }
  });

  it("parses base64url digests rather than hex", () => {
    const raw = fixture.proofs[0] as Record<string, string>;
    expect(raw["root"]).toMatch(/^[A-Za-z0-9_-]{43}$/);
    // Parsing normalises them to the hex every internal check uses.
    expect(parseInclusionProof(fixture.proofs[0]).root).toMatch(/^[0-9a-f]{64}$/);
  });

  it("rejects a proof whose leaf is not the one committed", async () => {
    const proof = parseInclusionProof(fixture.proofs[2]);
    expect(await verifyInclusion(encoder.encode("record 3"), proof, fixture.root)).toBe(false);
  });

  it("rejects a v2 proof presented against an unrelated root", async () => {
    const proof = parseInclusionProof(fixture.proofs[2]);
    expect(await verifyInclusion(encoder.encode("record 2"), proof, "0".repeat(64))).toBe(false);
  });

  it("refuses a version and algorithm that disagree", () => {
    const lying = { ...(fixture.proofs[0] as object), algorithm: "sha256-asciihex" };
    expect(() => parseInclusionProof(lying)).toThrow(/algorithm/);
  });

  it("refuses a malformed base64url digest", () => {
    const broken = { ...(fixture.proofs[0] as object), root: "not-a-valid-digest" };
    expect(() => parseInclusionProof(broken)).toThrow(/base64url/);
  });
});
