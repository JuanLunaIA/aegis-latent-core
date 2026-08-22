// Copyright (c) 2026 Juan Luna. All rights reserved.
// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

import { AegisProofError } from "./errors.js";
import {
  parseInclusionProof,
  resolveSubtleCrypto,
  verifyInclusion,
  verifyInclusionHash,
  verifyProofHeaders,
} from "./proof.js";
import type { AegisFetch, AegisProofVerificationOptions } from "./types.js";

export {
  parseInclusionProof,
  resolveSubtleCrypto,
  verifyInclusion,
  verifyInclusionHash,
  verifyProofHeaders,
};
export type { InclusionProofV1, Peak, ProofStep } from "./proof.js";

const HASH = /^[0-9a-f]{64}$/;

function verificationRoot(options: AegisProofVerificationOptions): string | undefined {
  if (!options.verifyProof) return undefined;
  const root = options.trustedMmrRoot;
  if (root === undefined || !HASH.test(root)) {
    throw new AegisProofError(
      "verifyProof requires trustedMmrRoot as 64 lowercase hexadecimal characters",
    );
  }
  return root;
}

/**
 * Wrap a standards-compatible fetch implementation with fail-closed proof checks.
 *
 * Streaming responses expose `X-Aegis-Evidence-Status: pending-terminal` because
 * their final leaf does not exist when HTTP headers are sent. They are returned
 * unchanged; callers can retrieve the terminal proof by state ID after consuming
 * the stream. Every other successful gateway response is verified before the
 * provider SDK can parse its body.
 */
export function proofVerifyingFetch(
  candidate: AegisFetch | undefined,
  options: AegisProofVerificationOptions,
): AegisFetch | undefined {
  const root = verificationRoot(options);
  if (root === undefined) return candidate;
  const baseFetch = candidate ?? globalThis.fetch?.bind(globalThis);
  if (baseFetch === undefined) {
    throw new AegisProofError("verifyProof requires a Fetch implementation");
  }
  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const response = await baseFetch(input, init);
    if (!response.ok) return response;
    if (response.headers.get("X-Aegis-Evidence-Status") === "pending-terminal") {
      return response;
    }
    await verifyProofHeaders(response.headers, root);
    return response;
  };
}
