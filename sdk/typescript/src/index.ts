// Copyright (c) 2026 Juan Luna. All rights reserved.
export {
  A2A_ENDPOINT,
  A2A_MODEL,
  A2A_RECEIPT_VERSION,
  a2aEnvelopeBytes,
  a2aLeafHash,
  parseAgentReceipt,
  verifyReceipt,
} from "./a2a.js";
export type { AgentReceipt } from "./a2a.js";
export { AegisProofError } from "./errors.js";
export {
  anthropicGatewayOptions,
  openAIGatewayOptions,
} from "./gateway.js";
export type {
  AegisGatewayConfig,
  AnthropicGatewayOptions,
  OpenAIGatewayOptions,
} from "./gateway.js";
export {
  parseInclusionProof,
  resolveSubtleCrypto,
  verifyInclusion,
  verifyInclusionHash,
  verifyProofHeaders,
} from "./proof.js";
export type { InclusionProofV1, Peak, ProofStep } from "./proof.js";
export {
  instrumentAnthropicOperation,
  instrumentOpenAIOperation,
  instrumentOperation,
} from "./providers.js";
export type { OperationHooks } from "./providers.js";
