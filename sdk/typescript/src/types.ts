// Copyright (c) 2026 Juan Luna. All rights reserved.
// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

import type { AegisGatewayConfig } from "./gateway.js";

export interface AegisProofVerificationOptions {
  /** Verify every non-streaming response proof before the official SDK parses it. */
  readonly verifyProof?: boolean;
  /** Independently trusted lowercase SHA-256 MMR root required by verifyProof. */
  readonly trustedMmrRoot?: string;
}

export interface AegisProviderConfig
  extends AegisGatewayConfig, AegisProofVerificationOptions {}

export type AegisFetch = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;
