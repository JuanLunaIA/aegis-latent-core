import { describe, expect, test } from "vitest";

import { proofSchema } from "../src/lib/contracts";
import { parsePrometheus } from "../src/lib/prometheus";

describe("runtime contracts", () => {
  test("portable proof rejects malformed hashes", () => {
    expect(() => proofSchema.parse({
      state_id:"r",node_hash:"x",leaf_hash:"a".repeat(64),leaf_index:0,leaf_count:1,
      root:"b".repeat(64),proof:{},signature_scheme:"hmac-sha256",signature_status:"valid",
    })).toThrow();
  });

  test("Prometheus parser admits only finite Aegis allowlist samples", () => {
    const parsed=parsePrometheus([
      "# HELP ignored help", "aegis_audit_chain_nodes 3", "process_resident_memory_bytes 99",
      "aegis_request_total{status=\"ok\"} NaN", "malformed",
    ].join("\n"));
    expect(parsed).toEqual([{name:"aegis_audit_chain_nodes",labels:"",value:3}]);
  });
});
