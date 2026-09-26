#!/usr/bin/env bash
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
# Read-only checks against the deployed gateway. Exit 0 only if every check passes.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
. ./kit.env
URL="https://$DNS_LABEL.$LOCATION.cloudapp.azure.com"
FAIL=0
check() { # name, expected-code, url [curl args...]
  local name=$1 want=$2 url=$3; shift 3
  local got; got=$(curl -s -o /dev/null -w '%{http_code}' -m 15 "$@" "$url" || true)
  if [ "$got" = "$want" ]; then echo "PASS  $name ($got)"; else echo "FAIL  $name (want $want, got $got)"; FAIL=1; fi
}
check "TLS + /health"                       200 "$URL/health"
check "plain HTTP redirects to HTTPS"       308 "http://$DNS_LABEL.$LOCATION.cloudapp.azure.com/health"
check "unauthenticated completion refused"  401 "$URL/v1/chat/completions" -X POST -H 'content-type: application/json' -d '{}'
[ "$FAIL" = 0 ] && echo "ALL CHECKS PASSED" || echo "CHECKS FAILED"
exit "$FAIL"
