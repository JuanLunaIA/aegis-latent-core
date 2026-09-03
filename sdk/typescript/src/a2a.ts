// Copyright (c) 2026 Juan Luna. All rights reserved.
// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
//
// Verify agent-to-agent execution receipts issued by `aegis.core.a2a`.
//
// A receipt is valid when both hold: the leaf named by its inclusion proof is
// the one the receipt's own fields reproduce, and that leaf is included under
// the root you supply. The first check is what stops a receipt quoting some
// other execution's leaf while asserting whatever metadata it likes.
//
// A valid receipt establishes inclusion under the root you supplied, and
// nothing else. It does not establish that the tool ran, that either agent
// identifier is authentic, that the caller was authorised, or that the
// timestamp is accurate — that is the issuer's unattested clock. Obtain the
// root independently of whoever handed you the receipt; verified against a
// root from the same party, a receipt shows internal consistency only.

import { AegisProofError } from "./errors.js";
import { parseInclusionProof, resolveSubtleCrypto, verifyInclusionHash } from "./proof.js";

export const A2A_RECEIPT_VERSION = "aegis-a2a-receipt-v1";
export const A2A_MODEL = "a2a";
export const A2A_ENDPOINT = "a2a.tool";

// Must match aegis/core/a2a.py exactly. These are hashed into the leaf, so a
// divergence does not yield a lenient verifier — it yields one that rejects
// every valid receipt.
const MAX_IDENTIFIER_CHARS = 128;
const LEAF_MAX_BYTES = 2048;

const HASH = /^[0-9a-f]{64}$/u;

export interface AgentReceipt {
  version: string;
  execution_id: string;
  caller_agent_id: string;
  target_agent_id: string;
  tool_name: string;
  input_hash: string;
  output_hash: string;
  timestamp: number;
  mmr_root: string;
  inclusion_proof: unknown;
}

function requireIdentifier(name: string, value: unknown): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new AegisProofError(`${name} must be a non-empty string`);
  }
  if (value.length > MAX_IDENTIFIER_CHARS) {
    throw new AegisProofError(`${name} exceeds ${MAX_IDENTIFIER_CHARS} characters`);
  }
  if (value.includes("\u0000")) {
    throw new AegisProofError(`${name} must not contain a NULL byte`);
  }
  return value;
}

function requireDigest(name: string, value: unknown): string {
  if (typeof value !== "string" || !HASH.test(value)) {
    throw new AegisProofError(`${name} must be a lowercase SHA-256 hex digest`);
  }
  return value;
}

/** Parse a transported receipt, refusing rather than defaulting any field. */
export function parseAgentReceipt(value: unknown): AgentReceipt {
  if (typeof value !== "object" || value === null) {
    throw new AegisProofError("receipt must be an object");
  }
  const raw = value as Record<string, unknown>;
  const timestamp = raw["timestamp"];
  if (typeof timestamp !== "number" || !Number.isFinite(timestamp)) {
    throw new AegisProofError("timestamp must be a finite number");
  }
  if (raw["inclusion_proof"] === undefined || raw["inclusion_proof"] === null) {
    throw new AegisProofError("inclusion_proof is required");
  }
  return {
    version: requireIdentifier("version", raw["version"]),
    execution_id: requireIdentifier("execution_id", raw["execution_id"]),
    caller_agent_id: requireIdentifier("caller_agent_id", raw["caller_agent_id"]),
    target_agent_id: requireIdentifier("target_agent_id", raw["target_agent_id"]),
    tool_name: requireIdentifier("tool_name", raw["tool_name"]),
    input_hash: requireDigest("input_hash", raw["input_hash"]),
    output_hash: requireDigest("output_hash", raw["output_hash"]),
    timestamp,
    mmr_root: requireDigest("mmr_root", raw["mmr_root"]),
    inclusion_proof: raw["inclusion_proof"],
  };
}

/**
 * Format a number the way Python's `f"{value:.6f}"` does.
 *
 * The envelope is hashed, so this must agree byte-for-byte with the issuer.
 * `toFixed(6)` matches for the finite, non-negative epoch values a timestamp
 * takes; exponential notation, which `toFixed` avoids, would not.
 */
function formatTimestamp(value: number): string {
  return value.toFixed(6);
}

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Canonical envelope bytes reproduced from a receipt's own fields. */
export function a2aEnvelopeBytes(receipt: AgentReceipt): Uint8Array {
  // Keys in sorted order, compact separators — matching Python's
  // json.dumps(sort_keys=True, separators=(",", ":")).
  const envelope =
    "{" +
    [
      `"caller_agent_id":${JSON.stringify(requireIdentifier("caller_agent_id", receipt.caller_agent_id))}`,
      `"execution_id":${JSON.stringify(requireIdentifier("execution_id", receipt.execution_id))}`,
      `"input_hash":${JSON.stringify(requireDigest("input_hash", receipt.input_hash))}`,
      `"output_hash":${JSON.stringify(requireDigest("output_hash", receipt.output_hash))}`,
      `"target_agent_id":${JSON.stringify(requireIdentifier("target_agent_id", receipt.target_agent_id))}`,
      `"timestamp":${JSON.stringify(formatTimestamp(receipt.timestamp))}`,
      `"tool_name":${JSON.stringify(requireIdentifier("tool_name", receipt.tool_name))}`,
      `"version":${JSON.stringify(A2A_RECEIPT_VERSION)}`,
    ].join(",") +
    "}";
  return utf8(envelope);
}

/**
 * SHA-256 of the MMR leaf the issuing ledger committed for this receipt.
 *
 * Mirrors `build_merkle_leaf` for the pinned A2A coordinates. The envelope is
 * bounded well under `LEAF_MAX_BYTES`, so the preview is a copy of it and the
 * result does not depend on the issuer's configuration.
 */
export async function a2aLeafHash(
  receipt: AgentReceipt,
  injectedSubtle?: SubtleCrypto,
): Promise<string> {
  const subtle = resolveSubtleCrypto(injectedSubtle);
  const envelope = a2aEnvelopeBytes(receipt);
  const envelopeHash = toHex(new Uint8Array(await subtle.digest("SHA-256", envelope)));
  const leaf =
    "{" +
    [
      `"endpoint":${JSON.stringify(A2A_ENDPOINT)}`,
      `"model":${JSON.stringify(A2A_MODEL)}`,
      `"request_hash":${JSON.stringify(envelopeHash)}`,
      `"request_preview_hex":${JSON.stringify(toHex(envelope.slice(0, LEAF_MAX_BYTES)))}`,
      `"request_size":${envelope.length}`,
      `"response_hash":""`,
      `"response_preview_hex":""`,
      `"response_size":0`,
      `"state_id":${JSON.stringify(receipt.execution_id)}`,
    ].join(",") +
    "}";
  return toHex(new Uint8Array(await subtle.digest("SHA-256", utf8(leaf))));
}

/**
 * Verify a receipt against a root obtained independently of its supplier.
 *
 * Resolves `true` only when the receipt reproduces the proven leaf and that
 * leaf is included under `trustedRoot`. Every failure resolves `false` rather
 * than throwing, so an error cannot be mistaken for a pass.
 */
export async function verifyReceipt(
  receipt: unknown,
  trustedRoot: string,
  injectedSubtle?: SubtleCrypto,
): Promise<boolean> {
  try {
    const parsed = parseAgentReceipt(receipt);
    if (parsed.version !== A2A_RECEIPT_VERSION) return false;
    if (parsed.mmr_root !== trustedRoot) return false;
    const subtle = resolveSubtleCrypto(injectedSubtle);
    const leafHash = await a2aLeafHash(parsed, subtle);
    const proof = parseInclusionProof(parsed.inclusion_proof);
    return await verifyInclusionHash(leafHash, proof, trustedRoot, subtle);
  } catch {
    return false;
  }
}
