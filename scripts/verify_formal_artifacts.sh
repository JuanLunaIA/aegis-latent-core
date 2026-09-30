#!/usr/bin/env bash
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
#
# The formal gate. Every check here has to be able to fail:
#
#   * Z3: each .smt2 file declares `; expect: <result> ...`, one word per
#     `(check-sat)`, and the whole output must equal it. At least one expected
#     result must be `sat`, so a model whose assumptions are contradictory -
#     which makes every query `unsat` - fails instead of passing.
#   * Lean: the file must type-check with no warning, `sorry` shows up as the
#     `sorryAx` axiom in `#print axioms` and fails the gate, only the standard
#     axioms are allowed, and the named theorems must all be reported.
#   * TLC: `specs/<model>.cfg` must finish with no error. Every other
#     `specs/<model>_*.cfg` is an expectation of failure: each INVARIANT it lists
#     is checked on its own and must be violated (TLC exit 12). Those are the
#     witnesses that the safety invariants are not vacuous, and the
#     counterexamples that show which design decision each one depends on.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPECS="$ROOT/specs"
TLA_JAR="${TLA_JAR:-$ROOT/.tools/tla2tools.jar}"
TLA_SOURCE_REVISION="${TLA_SOURCE_REVISION:-0894c3407f4717fec7cc18bde3bf3c857fa47333}"
MODEL_TIMEOUT_SECONDS="${MODEL_TIMEOUT_SECONDS:-300}"

# TLC's exit status for a safety (invariant) violation.
TLC_EXIT_SAFETY_VIOLATION=12

LEAN_FILE="$SPECS/AegisVerification.lean"
LEAN_REQUIRED_THEOREMS=(
  reachable_states_satisfy_invariant
  failed_requests_emit_nothing
  refused_requests_emit_nothing
  admission_requires_healthy
  durability_requires_healthy_commit
  fault_clears_only_by_repair
  emission_is_reachable
  commit_failure_is_reachable
  refusal_and_recovery_are_reachable
)
LEAN_ALLOWED_AXIOMS=" propext Quot.sound Classical.choice "

SMT_PROOFS=(aegis_invariants aegis_stream_buffer)
TLA_MODELS=(aegis_invariants aegis_ledger_immutability aegis_session_manager)

fail() {
  printf 'formal_gate=failed reason=%s\n' "$*" >&2
  exit 1
}

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
command -v unzip >/dev/null 2>&1 || {
  printf 'unzip is required to verify TLA+ tool provenance\n' >&2
  exit 127
}
unzip -p "$TLA_JAR" META-INF/MANIFEST.MF \
  | grep -F "X-Git-Revision: $TLA_SOURCE_REVISION" >/dev/null || {
  printf 'TLA+ tools source revision mismatch; expected %s\n' "$TLA_SOURCE_REVISION" >&2
  exit 1
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

printf 'z3_version=%s\n' "$(z3 --version)"
printf 'lean_version=%s\n' "$(lean --version | head -n 1)"
printf 'tla_jar_sha256=%s\n' "$(sha256sum "$TLA_JAR" | cut -d' ' -f1)"
printf 'tla_source_revision=%s\n' "$TLA_SOURCE_REVISION"

# ── Z3 ─────────────────────────────────────────────────────────────────────
for proof in "${SMT_PROOFS[@]}"; do
  file="$SPECS/${proof}.smt2"
  expected="$(sed -n 's/^; expect: //p' "$file")"
  [[ -n "$expected" ]] || fail "$proof.smt2 has no '; expect:' line"
  checks="$(grep -c '^(check-sat)' "$file" || true)"
  [[ "$(wc -w <<<"$expected")" -eq "$checks" ]] \
    || fail "$proof.smt2 expects $(wc -w <<<"$expected") results for $checks check-sat commands"
  grep -qw 'sat' <<<"$expected" \
    || fail "$proof.smt2 expects no 'sat' result, so nothing shows its assumptions are satisfiable"
  actual="$(timeout "${MODEL_TIMEOUT_SECONDS}s" z3 "$file" | tr '\n' ' ' | sed 's/ *$//')"
  printf 'z3_proof=%s expected="%s" actual="%s"\n' "$proof" "$expected" "$actual"
  [[ "$actual" == "$expected" ]] || fail "$proof.smt2 result mismatch"
done

# ── Lean ───────────────────────────────────────────────────────────────────
if grep -Eq '^[[:space:]]*(axiom|unsafe|@\[(implemented_by|extern))' "$LEAN_FILE"; then
  fail "AegisVerification.lean declares an axiom or an unchecked implementation"
fi
lean_output="$(timeout "${MODEL_TIMEOUT_SECONDS}s" lean "$LEAN_FILE" 2>&1)" \
  || { printf '%s\n' "$lean_output"; fail "lean rejected AegisVerification.lean"; }
printf '%s\n' "$lean_output"
if grep -Eq 'warning|error' <<<"$lean_output"; then
  fail "lean reported a warning or an error"
fi
for theorem in "${LEAN_REQUIRED_THEOREMS[@]}"; do
  line="$(grep -F "'AegisVerification.${theorem}'" <<<"$lean_output" || true)"
  [[ -n "$line" ]] || fail "lean did not report axioms for $theorem"
  if [[ "$line" == *"depends on axioms: ["* ]]; then
    axioms="${line#*depends on axioms: [}"
    axioms="${axioms%]*}"
    IFS=', ' read -r -a used <<<"$axioms"
    for axiom in "${used[@]}"; do
      [[ -z "$axiom" || "$LEAN_ALLOWED_AXIOMS" == *" $axiom "* ]] \
        || fail "$theorem depends on axiom $axiom"
    done
  fi
done
printf 'lean_result=verified theorems=%d\n' "${#LEAN_REQUIRED_THEOREMS[@]}"

# ── TLC ────────────────────────────────────────────────────────────────────
# -noGenerateSpecTE: an expected violation must not write a trace module into
# specs/, and -metadir keeps TLC's state files in the temporary directory.
run_tlc() {
  local model="$1" cfg="$2" label="$3"
  timeout "${MODEL_TIMEOUT_SECONDS}s" java -XX:+UseParallelGC -cp "$TLA_JAR" tlc2.TLC \
    -deadlock -workers auto -noGenerateSpecTE \
    -metadir "$WORK/$label" \
    -config "$cfg" \
    "$SPECS/${model}.tla"
}

for model in "${TLA_MODELS[@]}"; do
  printf 'tlc_model=%s config=%s.cfg expect=no_error\n' "$model" "$model"
  run_tlc "$model" "$SPECS/${model}.cfg" "$model"

  shopt -s nullglob
  expectation_cfgs=("$SPECS/${model}"_*.cfg)
  shopt -u nullglob
  [[ ${#expectation_cfgs[@]} -gt 0 ]] || fail "$model has no witness configuration"
  for cfg in "${expectation_cfgs[@]}"; do
    mapfile -t invariants < <(sed -n 's/^INVARIANT[[:space:]]\+\([A-Za-z0-9_]\+\).*/\1/p' "$cfg")
    [[ ${#invariants[@]} -gt 0 ]] || fail "$(basename "$cfg") lists no invariant"
    for invariant in "${invariants[@]}"; do
      single="$WORK/$(basename "$cfg" .cfg)_${invariant}.cfg"
      grep -Ev '^(INVARIANT|PROPERTY)[[:space:]]' "$cfg" >"$single"
      printf 'INVARIANT %s\n' "$invariant" >>"$single"
      printf 'tlc_model=%s config=%s invariant=%s expect=violated\n' \
        "$model" "$(basename "$cfg")" "$invariant"
      set +e
      output="$(run_tlc "$model" "$single" "$(basename "$single" .cfg)" 2>&1)"
      status=$?
      set -e
      if [[ $status -ne $TLC_EXIT_SAFETY_VIOLATION ]] \
        || ! grep -Fq "Invariant ${invariant} is violated" <<<"$output"; then
        printf '%s\n' "$output"
        fail "$(basename "$cfg"): $invariant was expected to be violated (tlc exit $status)"
      fi
      printf 'tlc_result=violated_as_expected states=%s\n' \
        "$(grep -o '[0-9]* distinct states found' <<<"$output" | head -n 1 | cut -d' ' -f1)"
    done
  done
done

printf 'formal_gate=passed\n'
