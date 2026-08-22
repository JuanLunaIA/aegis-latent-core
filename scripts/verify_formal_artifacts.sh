#!/usr/bin/env bash
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TLA_JAR="${TLA_JAR:-$ROOT/.tools/tla2tools.jar}"
MODEL_TIMEOUT_SECONDS="${MODEL_TIMEOUT_SECONDS:-60}"

command -v z3 >/dev/null 2>&1 || {
  printf 'z3 is required\n' >&2
  exit 127
}
command -v lean >/dev/null 2>&1 || {
  printf 'lean is required\n' >&2
  exit 127
}
[[ -f "$TLA_JAR" ]] || {
  printf 'TLA+ tools jar not found: %s\n' "$TLA_JAR" >&2
  exit 127
}

printf 'z3_version=%s\n' "$(z3 --version)"
printf 'lean_version=%s\n' "$(lean --version | head -n 1)"
printf 'tla_jar_sha256=%s\n' "$(sha256sum "$TLA_JAR" | cut -d' ' -f1)"

for proof in aegis_invariants aegis_stream_buffer; do
  z3_result="$(z3 "$ROOT/specs/${proof}.smt2")"
  printf 'z3_proof=%s z3_result=%s\n' "$proof" "$z3_result"
  [[ "$z3_result" == "unsat" ]]
done

timeout "${MODEL_TIMEOUT_SECONDS}s" lean "$ROOT/specs/AegisVerification.lean"
printf 'lean_result=verified\n'

for model in aegis_invariants aegis_ledger_immutability aegis_session_manager; do
  printf 'tlc_model=%s\n' "$model"
  timeout "${MODEL_TIMEOUT_SECONDS}s" java -XX:+UseParallelGC -cp "$TLA_JAR" tlc2.TLC \
    -deadlock \
    -config "$ROOT/specs/${model}.cfg" \
    "$ROOT/specs/${model}.tla"
done

printf 'formal_gate=passed\n'
