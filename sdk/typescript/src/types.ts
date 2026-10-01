// Copyright (c) 2026 Juan Luna.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.

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
