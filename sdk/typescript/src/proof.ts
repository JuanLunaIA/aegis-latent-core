// Copyright (c) 2026 Juan Luna. All rights reserved.
import { AegisProofError } from "./errors.js";

export interface ProofStep {
  readonly sibling_hash: string;
  readonly direction: "L" | "R";
}

export interface Peak {
  readonly height: number;
  readonly hash: string;
}

/**
 * A self-contained MMR inclusion proof, v1 or v2.
 *
 * v1 hashes a leaf as `SHA-256(payload)` and a node as
 * `SHA-256(ascii(left_hex) || ascii(right_hex))`, with nothing distinguishing
 * the two cases — so a leaf whose payload is the 128-character concatenation of
 * two child digests hashes to the interior node over them. v2 prefixes each
 * input with a domain tag and hashes raw 32-byte digests, per RFC 6962 §2.1.
 *
 * The interface keeps both because historical proofs must keep verifying; the
 * version field selects the construction and is never inferred.
 */
export interface InclusionProofV1 {
  readonly version: "aegis-mmr-inclusion-v1" | "aegis-mmr-inclusion-v2";
  readonly algorithm: "sha256-asciihex" | "sha256-binary-domain-separated";
  readonly leaf_index: number;
  readonly leaf_count: number;
  readonly peak_index: number;
  readonly path: readonly ProofStep[];
  readonly peaks: readonly Peak[];
  readonly root: string;
}

const PROOF_KEYS = [
  "algorithm",
  "leaf_count",
  "leaf_index",
  "path",
  "peak_index",
  "peaks",
  "root",
  "version",
] as const;
const HASH = /^[0-9a-f]{64}$/;
const B64U_DIGEST = /^[A-Za-z0-9_-]{43}$/;
const encoder = new TextEncoder();

const PROOF_V1 = "aegis-mmr-inclusion-v1" as const;
const PROOF_V2 = "aegis-mmr-inclusion-v2" as const;
const ALGORITHM_V1 = "sha256-asciihex" as const;
const ALGORITHM_V2 = "sha256-binary-domain-separated" as const;

const DOMAIN_LEAF = 0x00;
const DOMAIN_NODE = 0x01;
const DOMAIN_ROOT = 0x02;

function hexToBytes(value: string): Uint8Array {
  const out = new Uint8Array(value.length / 2);
  for (let index = 0; index < out.length; index += 1) {
    out[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
}

/** Prefix `tag` onto the concatenated parts, the v2 hashing input shape. */
function domainInput(tag: number, parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 1);
  const buffer = new Uint8Array(total);
  buffer[0] = tag;
  let offset = 1;
  for (const part of parts) {
    buffer.set(part, offset);
    offset += part.length;
  }
  return buffer;
}

/** Decode a 43-character unpadded base64url v2 digest to lowercase hex. */
function b64uDigestToHex(value: unknown, label: string): string {
  if (typeof value !== "string" || !B64U_DIGEST.test(value)) {
    throw new AegisProofError(`${label} must be 43-character unpadded base64url`);
  }
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=";
  const decoded = globalThis.atob(padded);
  if (decoded.length !== 32) throw new AegisProofError(`${label} must decode to 32 bytes`);
  return Array.from(decoded, (character) =>
    character.charCodeAt(0).toString(16).padStart(2, "0"),
  ).join("");
}

function objectRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new AegisProofError(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new AegisProofError("proof object contains missing or unknown fields");
  }
}

function integer(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value)) {
    throw new AegisProofError(`${label} must be a safe integer`);
  }
  return value as number;
}

function hash(value: unknown, label: string): string {
  if (typeof value !== "string" || !HASH.test(value)) {
    throw new AegisProofError(`${label} must be 64 lowercase hexadecimal characters`);
  }
  return value;
}

export function parseInclusionProof(value: unknown): InclusionProofV1 {
  const proof = objectRecord(value, "proof");
  exactKeys(proof, PROOF_KEYS);
  const version = proof["version"];
  const isV2 = version === PROOF_V2;
  if (version !== PROOF_V1 && !isV2) {
    throw new AegisProofError("unsupported MMR proof version");
  }
  // The pair must agree; a proof claiming one version with the other's
  // algorithm is malformed, not something to resolve in the caller's favour.
  if (proof["algorithm"] !== (isV2 ? ALGORITHM_V2 : ALGORITHM_V1)) {
    throw new AegisProofError("unsupported MMR hash algorithm");
  }
  // v2 transmits digests as base64url; normalise to the hex every check uses.
  const digest = (value: unknown, label: string): string =>
    isV2 ? b64uDigestToHex(value, label) : hash(value, label);
  if (!Array.isArray(proof["path"]) || !Array.isArray(proof["peaks"])) {
    throw new AegisProofError("path and peaks must be arrays");
  }
  const path = proof["path"].map((raw): ProofStep => {
    const step = objectRecord(raw, "path step");
    exactKeys(step, ["direction", "sibling_hash"]);
    if (step["direction"] !== "L" && step["direction"] !== "R") {
      throw new AegisProofError("path direction must be L or R");
    }
    return { direction: step["direction"], sibling_hash: digest(step["sibling_hash"], "sibling") };
  });
  const peaks = proof["peaks"].map((raw): Peak => {
    const peak = objectRecord(raw, "peak");
    exactKeys(peak, ["hash", "height"]);
    return { hash: digest(peak["hash"], "peak hash"), height: integer(peak["height"], "peak height") };
  });
  return {
    version: isV2 ? PROOF_V2 : PROOF_V1,
    algorithm: isV2 ? ALGORITHM_V2 : ALGORITHM_V1,
    leaf_index: integer(proof["leaf_index"], "leaf_index"),
    leaf_count: integer(proof["leaf_count"], "leaf_count"),
    peak_index: integer(proof["peak_index"], "peak_index"),
    path,
    peaks,
    root: digest(proof["root"], "root"),
  };
}

export function resolveSubtleCrypto(injected?: SubtleCrypto): SubtleCrypto {
  const subtle = injected ?? globalThis.crypto?.subtle;
  if (subtle === undefined) {
    throw new AegisProofError("Web Crypto SubtleCrypto is unavailable");
  }
  return subtle;
}

function toHex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256(data: Uint8Array, subtle: SubtleCrypto): Promise<string> {
  return toHex(await subtle.digest("SHA-256", data));
}

function expectedHeights(leafCount: number): number[] {
  const result: number[] = [];
  for (let bit = Math.floor(Math.log2(leafCount)); bit >= 0; bit -= 1) {
    const power = 2 ** bit;
    if (Math.floor(leafCount / power) % 2 === 1) {
      result.push(bit);
    }
  }
  return result;
}

export async function verifyInclusion(
  leaf: Uint8Array,
  proof: InclusionProofV1,
  trustedRoot: string,
  injectedSubtle?: SubtleCrypto,
): Promise<boolean> {
  const subtle = resolveSubtleCrypto(injectedSubtle);
  // Digest the leaf under the scheme the proof declares, so a proof of one
  // version can never be replayed against the other's leaf digest.
  const leafHash = proof.version === PROOF_V2
    ? await sha256(domainInput(DOMAIN_LEAF, [leaf]), subtle)
    : await sha256(leaf, subtle);
  return verifyInclusionHash(leafHash, proof, trustedRoot, subtle);
}

export async function verifyInclusionHash(
  leafHash: string,
  proof: InclusionProofV1,
  trustedRoot: string,
  injectedSubtle?: SubtleCrypto,
): Promise<boolean> {
  const isV2 = proof.version === PROOF_V2;
  if (proof.algorithm !== (isV2 ? ALGORITHM_V2 : ALGORITHM_V1)) return false;
  if (!HASH.test(trustedRoot) || proof.root !== trustedRoot || proof.leaf_count < 1) return false;
  if (!HASH.test(leafHash)) return false;
  if (proof.leaf_index < 0 || proof.leaf_index >= proof.leaf_count) return false;
  const heights = expectedHeights(proof.leaf_count);
  if (proof.peaks.length !== heights.length) return false;
  if (proof.peak_index < 0 || proof.peak_index >= proof.peaks.length) return false;
  if (proof.peaks.some((peak, index) => peak.height !== heights[index] || !HASH.test(peak.hash))) return false;

  const mountainStart = heights
    .slice(0, proof.peak_index)
    .reduce((total, height) => total + 2 ** height, 0);
  const mountainHeight = heights[proof.peak_index];
  if (mountainHeight === undefined) return false;
  const mountainSize = 2 ** mountainHeight;
  if (proof.leaf_index < mountainStart || proof.leaf_index >= mountainStart + mountainSize) return false;
  if (proof.path.length !== mountainHeight) return false;

  const subtle = resolveSubtleCrypto(injectedSubtle);
  const localIndex = proof.leaf_index - mountainStart;
  let current = leafHash;
  for (let level = 0; level < proof.path.length; level += 1) {
    const step = proof.path[level];
    if (step === undefined || !HASH.test(step.sibling_hash)) return false;
    const expectedDirection = Math.floor(localIndex / 2 ** level) % 2 === 0 ? "R" : "L";
    if (step.direction !== expectedDirection) return false;
    const [left, right] = step.direction === "R"
      ? [current, step.sibling_hash]
      : [step.sibling_hash, current];
    current = isV2
      ? await sha256(domainInput(DOMAIN_NODE, [hexToBytes(left), hexToBytes(right)]), subtle)
      : await sha256(encoder.encode(left + right), subtle);
  }
  if (current !== proof.peaks[proof.peak_index]?.hash) return false;
  const root = isV2
    ? await sha256(
        domainInput(DOMAIN_ROOT, proof.peaks.map((peak) => hexToBytes(peak.hash))),
        subtle,
      )
    : await sha256(encoder.encode(proof.peaks.map((peak) => peak.hash).join("")), subtle);
  return root === trustedRoot;
}

function base64UrlBytes(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new AegisProofError("invalid base64url header");
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  const decoded = globalThis.atob(padded);
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
}

export async function verifyProofHeaders(
  headers: Headers | Readonly<Record<string, string>>,
  trustedRoot: string,
  injectedSubtle?: SubtleCrypto,
): Promise<InclusionProofV1> {
  const get = (name: string): string | null => {
    if (headers instanceof Headers) return headers.get(name);
    const entry = Object.entries(headers).find(([key]) => key.toLowerCase() === name.toLowerCase());
    return entry?.[1] ?? null;
  };
  const leafHeader = get("X-Aegis-MMR-Leaf");
  const proofHeader = get("X-Aegis-MMR-Proof");
  const rootHeader = get("X-Aegis-MMR-Root");
  if (leafHeader === null || proofHeader === null || rootHeader === null) {
    throw new AegisProofError("required Aegis proof headers are missing");
  }
  if (rootHeader !== trustedRoot) throw new AegisProofError("gateway root differs from trusted root");
  if (!HASH.test(leafHeader)) throw new AegisProofError("leaf header is not a lowercase SHA-256 digest");
  let decoded: unknown;
  try {
    decoded = JSON.parse(new TextDecoder().decode(base64UrlBytes(proofHeader)));
  } catch (error: unknown) {
    throw new AegisProofError(`proof header is not valid JSON: ${String(error)}`);
  }
  const proof = parseInclusionProof(decoded);
  if (!(await verifyInclusionHash(leafHeader, proof, trustedRoot, injectedSubtle))) {
    throw new AegisProofError("MMR inclusion verification failed");
  }
  return proof;
}
