import { z } from "zod";

const hash = z.string().regex(/^[0-9a-f]{64}$/);

export const serviceHealthSchema = z.object({status: z.string()}).passthrough();
export const auditHealthSchema = z.object({
  status: z.string(), node_count: z.number().int().nonnegative(),
  legal_admissibility: z.string(), fault_state: z.string(),
  scope: z.string().optional(), window_anchor_hash: z.string().optional(),
  full_history_retained: z.boolean().optional(),
});
export const integritySchema = z.object({
  valid: z.boolean(), error_index: z.number().int().nullable(),
  node_count: z.number().int().nonnegative(), tail_hash: z.string(),
  legal_admissibility: z.string(), scope: z.string().default("retained-memory-window"),
  window_anchor_hash: z.string().default(""), full_history_retained: z.boolean().default(false),
});
export const auditNodeSchema = z.object({
  index: z.number().int().nonnegative(), timestamp: z.number(), state_id: z.string(),
  entropy: z.number(), payload_hash: z.string(), node_hash: hash,
  tenant_id: z.string(), sampling_params: z.record(z.string(), z.unknown()),
  merkle_root: z.string(), signature_scheme: z.string(), signature_status: z.string(),
  model: z.string(), endpoint: z.string(), phi_scrubbed: z.boolean(),
  token_count: z.number().int().nonnegative(), latency_ms: z.number().nonnegative().nullable(),
  terminal_outcome: z.string().nullable(), redaction_hits: z.record(z.string(), z.number().int().nonnegative()),
  cid: z.string().startsWith("b"),
});
export const nodesSchema = z.array(auditNodeSchema);
export const proofSchema = z.object({
  state_id: z.string(), node_hash: hash, leaf_hash: hash,
  leaf_index: z.number().int().nonnegative(), leaf_count: z.number().int().positive(),
  root: hash, proof: z.record(z.string(), z.unknown()),
  signature_scheme: z.string(), signature_status: z.string(),
});
export const metricSchema = z.object({name: z.string(), labels: z.string(), value: z.number()});
export const metricsSchema = z.object({scraped_at: z.string(), samples: z.array(metricSchema)});
export const rawEvidenceSchema = z.object({
  node_hash: hash, cid: z.string().startsWith("b"), media_type: z.literal("application/vnd.ipld.dag-cbor"),
  jcs_json: z.string(), dag_cbor_base64: z.string(), dag_cbor_sha256: hash,
});

export type AuditNode = z.infer<typeof auditNodeSchema>;
export type ProofResponse = z.infer<typeof proofSchema>;
export type RawEvidence = z.infer<typeof rawEvidenceSchema>;
