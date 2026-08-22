// Copyright (c) 2026 Juan Luna. All rights reserved.
// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

import OfficialAnthropic, { type ClientOptions } from "@anthropic-ai/sdk";

import { anthropicGatewayOptions } from "./gateway.js";
import { proofVerifyingFetch } from "./verifier.js";
import type { AegisFetch, AegisProviderConfig } from "./types.js";

export type AegisAnthropicOptions = Omit<
  ClientOptions,
  "apiKey" | "authToken" | "baseURL" | "defaultHeaders" | "fetch"
> & AegisProviderConfig & {
  readonly fetch?: AegisFetch;
};

/**
 * The official Anthropic client routed to Aegis' native `/v1/messages` ingress.
 * Native message overloads, streams, errors, and response types are inherited
 * from the installed `@anthropic-ai/sdk` peer dependency.
 */
export class Anthropic extends OfficialAnthropic {
  constructor(options: AegisAnthropicOptions) {
    const {
      aegisApiKey,
      gatewayUrl,
      tenantId,
      sessionId,
      traceContext,
      defaultHeaders,
      verifyProof,
      trustedMmrRoot,
      fetch,
      ...officialOptions
    } = options;
    const gateway = anthropicGatewayOptions({
      aegisApiKey,
      gatewayUrl,
      tenantId,
      ...(sessionId === undefined ? {} : { sessionId }),
      ...(traceContext === undefined ? {} : { traceContext }),
      ...(defaultHeaders === undefined ? {} : { defaultHeaders }),
    });
    const verifiedFetch = proofVerifyingFetch(fetch, {
      ...(verifyProof === undefined ? {} : { verifyProof }),
      ...(trustedMmrRoot === undefined ? {} : { trustedMmrRoot }),
    });
    super({
      ...officialOptions,
      ...gateway,
      ...(verifiedFetch === undefined ? {} : { fetch: verifiedFetch as ClientOptions["fetch"] }),
    });
  }
}

export default Anthropic;
