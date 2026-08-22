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

export interface InclusionProofV1 {
  readonly version: "aegis-mmr-inclusion-v1";
  readonly algorithm: "sha256-asciihex";
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
const encoder = new TextEncoder();

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
  if (proof["version"] !== "aegis-mmr-inclusion-v1") {
    throw new AegisProofError("unsupported MMR proof version");
  }
  if (proof["algorithm"] !== "sha256-asciihex") {
    throw new AegisProofError("unsupported MMR hash algorithm");
  }
  if (!Array.isArray(proof["path"]) || !Array.isArray(proof["peaks"])) {
    throw new AegisProofError("path and peaks must be arrays");
  }
  const path = proof["path"].map((raw): ProofStep => {
    const step = objectRecord(raw, "path step");
    exactKeys(step, ["direction", "sibling_hash"]);
    if (step["direction"] !== "L" && step["direction"] !== "R") {
      throw new AegisProofError("path direction must be L or R");
    }
    return { direction: step["direction"], sibling_hash: hash(step["sibling_hash"], "sibling") };
  });
  const peaks = proof["peaks"].map((raw): Peak => {
    const peak = objectRecord(raw, "peak");
    exactKeys(peak, ["hash", "height"]);
    return { hash: hash(peak["hash"], "peak hash"), height: integer(peak["height"], "peak height") };
  });
  return {
    version: proof["version"],
    algorithm: proof["algorithm"],
    leaf_index: integer(proof["leaf_index"], "leaf_index"),
    leaf_count: integer(proof["leaf_count"], "leaf_count"),
    peak_index: integer(proof["peak_index"], "peak_index"),
    path,
    peaks,
    root: hash(proof["root"], "root"),
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
  return verifyInclusionHash(await sha256(leaf, subtle), proof, trustedRoot, subtle);
}

export async function verifyInclusionHash(
  leafHash: string,
  proof: InclusionProofV1,
  trustedRoot: string,
  injectedSubtle?: SubtleCrypto,
): Promise<boolean> {
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
    const combined = step.direction === "R"
      ? current + step.sibling_hash
      : step.sibling_hash + current;
    current = await sha256(encoder.encode(combined), subtle);
  }
  if (current !== proof.peaks[proof.peak_index]?.hash) return false;
  const root = await sha256(encoder.encode(proof.peaks.map((peak) => peak.hash).join("")), subtle);
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
