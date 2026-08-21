#!/usr/bin/env bash
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
set -euo pipefail
export GH_FORCE_TTY=0
export NO_COLOR=1

REPOSITORY="${1:-JuanLunaIA/aegis-latent-core}"
OUTPUT_DIR="${2:-evidence/github_status_2026-08-20}"
mkdir -p "$OUTPUT_DIR"

capture() {
  local name="$1"
  local endpoint="$2"
  local output="$OUTPUT_DIR/$name.json"
  local error_output="$OUTPUT_DIR/$name.stderr.txt"
  if gh api \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$endpoint" >"$output" 2>"$error_output"; then
    rm -f "$error_output"
    printf '%s\tAVAILABLE\n' "$name" >&2
  else
    printf '{"endpoint":"%s","status":"UNAVAILABLE","stderr_file":"%s"}\n' \
      "$endpoint" "$(basename "$error_output")" >"$output"
    printf '%s\tUNAVAILABLE\n' "$name" >&2
  fi
}

capture repository "repos/$REPOSITORY"
capture actions_permissions "repos/$REPOSITORY/actions/permissions"
capture actions_runs "repos/$REPOSITORY/actions/runs?per_page=100"
capture branch_protection "repos/$REPOSITORY/branches/main/protection"
capture dependabot_alerts "repos/$REPOSITORY/dependabot/alerts?state=open&per_page=100"
capture code_scanning_alerts "repos/$REPOSITORY/code-scanning/alerts?state=open&per_page=100"
capture secret_scanning_alerts "repos/$REPOSITORY/secret-scanning/alerts?state=open&per_page=100"
capture security_advisories "repos/$REPOSITORY/security-advisories?state=published&per_page=100"
capture workflows "repos/$REPOSITORY/actions/workflows?per_page=100"

python3 - "$OUTPUT_DIR" "$REPOSITORY" <<'PY'
import json
import sys
from pathlib import Path

output_dir = Path(sys.argv[1])
repository = sys.argv[2]
actions_path = output_dir / "actions_runs.json"
if actions_path.exists():
    actions_payload = json.loads(actions_path.read_text(encoding="utf-8"))
    if isinstance(actions_payload, dict) and "workflow_runs" in actions_payload:
        actions_payload = {
            "total_count": actions_payload.get("total_count", 0),
            "workflow_runs": [
                {
                    key: run.get(key)
                    for key in (
                        "id",
                        "name",
                        "head_branch",
                        "head_sha",
                        "status",
                        "conclusion",
                        "event",
                        "created_at",
                        "updated_at",
                        "html_url",
                    )
                }
                for run in actions_payload.get("workflow_runs", [])
            ],
        }
        actions_path.write_text(
            json.dumps(actions_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
summary = {
    "schema": "aegis-github-security-status-v1",
    "repository": repository,
    "sources": {},
}
for path in sorted(output_dir.glob("*.json")):
    if path.name == "SUMMARY.json":
        continue
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        summary["sources"][path.stem] = {
            "status": "INVALID_JSON",
            "error": str(exc),
        }
        continue
    if isinstance(payload, dict) and payload.get("status") == "UNAVAILABLE":
        summary["sources"][path.stem] = payload
    elif isinstance(payload, list):
        summary["sources"][path.stem] = {
            "status": "AVAILABLE",
            "items": len(payload),
        }
    elif isinstance(payload, dict) and "total_count" in payload:
        summary["sources"][path.stem] = {
            "status": "AVAILABLE",
            "items": payload["total_count"],
        }
    else:
        summary["sources"][path.stem] = {"status": "AVAILABLE"}
(output_dir / "SUMMARY.json").write_text(
    json.dumps(summary, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
    newline="\n",
)
print(json.dumps(summary, sort_keys=True))
PY
