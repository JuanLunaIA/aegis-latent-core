#!/usr/bin/env bash
# Regenerate aegis/core/audit_node_pb2.py from aegis/core/audit_node.proto.
#
# REG-056: the generated module is tracked in the tree and nothing in the
# repository could previously regenerate it — no protoc invocation, no Makefile
# target, no buf/grpc_tools configuration — so the .proto and the checked-in
# descriptor could drift apart silently. This script is the regeneration path.
#
# It does NOT run in CI: `grpcio-tools` is not a declared dependency of this
# repository, and adding a build-time code generator to the published
# verification surface is a packaging decision (the alternative, deleting the
# generated file and the .proto with it, is tracked in the registry). The
# freshness test (`tests/test_audit_node_proto_freshness.py`) verifies the
# checked-in pair without needing protoc, which is what CI can assert.
#
# Usage:
#   python -m pip install grpcio-tools        # or run inside an env that has it
#   bash scripts/regenerate_protobuf.sh
#   ! git diff --quiet                      # then review the diff before committing
#
# `audit_node_pb2.py` is listed in SKIP_NAMES in scripts/apply_license_headers.py,
# so it carries the protoc banner rather than this repository's AGPL header.

set -euo pipefail

PYTHON_BIN="${PYTHON:-python3}"
PROTO_PATH="aegis/core/audit_node.proto"
OUT_DIR="aegis/core"

if [ ! -f "$PROTO_PATH" ]; then
    echo "error: $PROTO_PATH not found; run this script from the repository root" >&2
    exit 2
fi

if ! "$PYTHON_BIN" -c "import grpc_tools.protoc" >/dev/null 2>&1; then
    echo "error: grpc_tools is not importable in $PYTHON_BIN." >&2
    echo "Install it into that interpreter (python -m pip install grpcio-tools) and re-run." >&2
    echo "The checked-in descriptor is verified without protoc by" >&2
    echo "  $PYTHON_BIN -m pytest tests/test_audit_node_proto_freshness.py -q" >&2
    exit 2
fi

echo "regenerating $OUT_DIR/audit_node_pb2.py from $PROTO_PATH"
"$PYTHON_BIN" -m grpc_tools.protoc \
    --python_out="$OUT_DIR" \
    --proto_path="$OUT_DIR" \
    "$PROTO_PATH"

echo "done. The generated file carries the protoc banner by design:"
echo "  head -3 $OUT_DIR/audit_node_pb2.py"
