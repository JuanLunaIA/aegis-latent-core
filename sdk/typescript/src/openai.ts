// Copyright (c) 2026 Juan Luna. All rights reserved.
// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

import OfficialOpenAI, { type ClientOptions } from "openai";

import { openAIGatewayOptions } from "./gateway.js";
import { proofVerifyingFetch } from "./verifier.js";
import type { AegisFetch, AegisProviderConfig } from "./types.js";

export type AegisOpenAIOptions = Omit<
  ClientOptions,
  "apiKey" | "baseURL" | "defaultHeaders" | "fetch"
> & AegisProviderConfig & {
  readonly fetch?: AegisFetch;
};

/**
 * The official OpenAI client with only constructor routing changed for Aegis.
 * All resources, overloads, streaming iterators, errors, and response types are
 * inherited directly from the installed `openai` peer dependency.
 */
export class OpenAI extends OfficialOpenAI {
  constructor(options: AegisOpenAIOptions) {
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
    const gateway = openAIGatewayOptions({
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

export default OpenAI;
