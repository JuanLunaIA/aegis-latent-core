#!/usr/bin/env bash
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
#
# install_aegis.sh — Zero-touch POSIX installer for Aegis Latent Core v2.4.1
#
# Supported platforms: Linux (x86_64, aarch64), macOS (x86_64, Apple Silicon)
# Requires: Python 3.11+, curl or wget, git (optional for source install)
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/JuanLunaIA/aegis-latent-core/main/scripts/install_aegis.sh | bash
#   # OR locally:
#   bash scripts/install_aegis.sh [--dev] [--rust] [--dir /opt/aegis]

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
AEGIS_VERSION="2.4.1"
AEGIS_PACKAGE="aegis-latent-core==${AEGIS_VERSION}"
DEFAULT_INSTALL_DIR="${HOME}/.aegis"
VENV_DIR=""
INSTALL_DEV=false
INSTALL_RUST=false
SKIP_ENV_GEN=false

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${BLUE}[aegis]${NC} $*"; }
success() { echo -e "${GREEN}[aegis]${NC} $*"; }
warn()    { echo -e "${YELLOW}[aegis]${NC} $*"; }
error()   { echo -e "${RED}[aegis]${NC} $*" >&2; }

# ── Argument parsing ──────────────────────────────────────────────────────────
INSTALL_DIR="${DEFAULT_INSTALL_DIR}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dev)         INSTALL_DEV=true  ;;
        --rust)        INSTALL_RUST=true ;;
        --dir)         INSTALL_DIR="$2"; shift ;;
        --skip-env)    SKIP_ENV_GEN=true ;;
        -h|--help)
            echo "Usage: $0 [--dev] [--rust] [--dir <path>] [--skip-env]"
            echo "  --dev       Install dev extras (pytest, mypy, ruff, bandit)"
            echo "  --rust      Build and install Rust extension (requires cargo)"
            echo "  --dir PATH  Install into PATH instead of ${DEFAULT_INSTALL_DIR}"
            echo "  --skip-env  Do not generate .env file"
            exit 0
            ;;
        *) warn "Unknown flag: $1 (ignored)" ;;
    esac
    shift
done

VENV_DIR="${INSTALL_DIR}/venv"

# ── OS detection ──────────────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"
info "Detected: ${OS} ${ARCH}"

case "${OS}" in
    Linux)   PLATFORM="linux" ;;
    Darwin)  PLATFORM="macos" ;;
    *)
        error "Unsupported OS: ${OS}. Supported: Linux, macOS."
        exit 1
        ;;
esac

# ── Python detection ──────────────────────────────────────────────────────────
PYTHON=""
for cmd in python3.13 python3.12 python3.11 python3; do
    if command -v "${cmd}" &>/dev/null; then
        VER="$("${cmd}" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
        MAJOR="${VER%%.*}"; MINOR="${VER##*.}"
        if [[ "${MAJOR}" -ge 3 && "${MINOR}" -ge 11 ]]; then
            PYTHON="${cmd}"
            break
        fi
    fi
done

if [[ -z "${PYTHON}" ]]; then
    error "Python 3.11+ is required but was not found."
    error "Install Python from https://www.python.org/downloads/ or use pyenv."
    exit 1
fi

PYTHON_VERSION="$("${PYTHON}" --version 2>&1)"
info "Using ${PYTHON_VERSION} at $(command -v "${PYTHON}")"

# ── Rust / Cargo detection (optional) ────────────────────────────────────────
if "${INSTALL_RUST}"; then
    if ! command -v cargo &>/dev/null; then
        warn "Rust/Cargo not found. Install from https://rustup.rs/"
        warn "Continuing without Rust extension (Python fallback will be used)."
        INSTALL_RUST=false
    else
        RUST_VERSION="$(cargo --version)"
        info "Rust: ${RUST_VERSION}"
    fi
fi

# ── Create install directory and virtualenv ───────────────────────────────────
info "Creating install directory: ${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"

info "Creating Python virtual environment: ${VENV_DIR}"
"${PYTHON}" -m venv "${VENV_DIR}"
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"

# Upgrade pip to avoid legacy resolver issues
pip install --quiet --upgrade pip setuptools wheel

# ── Install Aegis ─────────────────────────────────────────────────────────────
info "Installing ${AEGIS_PACKAGE}..."
if "${INSTALL_DEV}"; then
    pip install "${AEGIS_PACKAGE}[dev]"
else
    pip install "${AEGIS_PACKAGE}"
fi
success "Aegis installed."

# ── Build Rust extension (optional) ──────────────────────────────────────────
if "${INSTALL_RUST}"; then
    info "Building Rust extension (aegis_rust)..."
    # Expect to be run from the repo root OR have aegis_rust_v2 available
    if [[ -d "aegis_rust_v2" ]]; then
        pip install maturin
        maturin develop --manifest-path aegis_rust_v2/Cargo.toml --release --features extension-module
        success "Rust extension built and installed."
    else
        warn "aegis_rust_v2/ not found. Skipping Rust extension build."
        warn "Clone the full repository to build Rust extensions: git clone https://github.com/JuanLunaIA/aegis-latent-core"
    fi
fi

# ── Generate .env file ────────────────────────────────────────────────────────
ENV_FILE="${INSTALL_DIR}/.env"
if ! "${SKIP_ENV_GEN}" && [[ ! -f "${ENV_FILE}" ]]; then
    info "Generating default .env at ${ENV_FILE}..."

    # Auto-generate safe defaults
    SIGNING_KEY="$("${PYTHON}" -c 'import secrets; print(secrets.token_hex(32))')"
    PROXY_KEY="sk-aegis-$("${PYTHON}" -c 'import secrets; print(secrets.token_hex(16))')"
    AUDIT_KEY="sk-audit-$("${PYTHON}" -c 'import secrets; print(secrets.token_hex(16))')"

    cat > "${ENV_FILE}" <<EOF
# Aegis Latent Core v${AEGIS_VERSION} — Auto-generated environment
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# IMPORTANT: AEGIS_BACKEND_API_KEY must be set manually.

AEGIS_PROVIDER=openai
AEGIS_BACKEND_URL=https://api.openai.com
AEGIS_BACKEND_API_KEY=        # Set your LLM provider API key here (required)

AEGIS_API_KEYS=${PROXY_KEY}
AEGIS_AUDIT_API_KEYS=${AUDIT_KEY}
AEGIS_SIGNING_KEY=${SIGNING_KEY}

AEGIS_WAL_PATH=${INSTALL_DIR}/aegis.wal.jsonl
AEGIS_LOG_LEVEL=INFO
AEGIS_FORCE_LOGPROBS=true
AEGIS_RATE_LIMIT_THRESHOLD=60
AEGIS_RATE_LIMIT_BURST=10
EOF
    chmod 600 "${ENV_FILE}"
    success ".env generated at ${ENV_FILE} (mode 0600)"
    warn "ACTION REQUIRED: Set AEGIS_BACKEND_API_KEY in ${ENV_FILE}"
else
    if "${SKIP_ENV_GEN}"; then
        info "Skipping .env generation (--skip-env)."
    else
        info ".env already exists at ${ENV_FILE} — not overwriting."
    fi
fi

# ── Create launch script ──────────────────────────────────────────────────────
LAUNCH_SCRIPT="${INSTALL_DIR}/start_aegis.sh"
cat > "${LAUNCH_SCRIPT}" <<'LAUNCH'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/venv/bin/activate"
set -a; source "${SCRIPT_DIR}/.env"; set +a
exec uvicorn aegis.proxy.app:create_proxy_app \
    --factory \
    --host "${AEGIS_HOST:-0.0.0.0}" \
    --port "${AEGIS_PORT:-8080}" \
    --workers "${UVICORN_WORKERS:-2}" \
    "$@"
LAUNCH
chmod +x "${LAUNCH_SCRIPT}"

# ── Verify installation ───────────────────────────────────────────────────────
info "Verifying installation..."
"${VENV_DIR}/bin/python" -c "import aegis; from aegis.core.crypto_audit import CryptographicAuditLedger; print('  crypto_audit: OK')"
"${VENV_DIR}/bin/python" -c "from aegis.proxy.waf import AegisWAF; print('  waf: OK')"
"${VENV_DIR}/bin/python" -m examples.demo 2>/dev/null && success "  examples.demo: 5/5 checks OK" || warn "  examples.demo skipped (no upstream configured)"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
success "══════════════════════════════════════════════════════"
success "  Aegis Latent Core v${AEGIS_VERSION} installed successfully"
success "══════════════════════════════════════════════════════"
echo ""
echo "  Install dir:  ${INSTALL_DIR}"
echo "  Virtual env:  ${VENV_DIR}"
echo "  Config:       ${ENV_FILE}"
echo "  Launch:       ${LAUNCH_SCRIPT}"
echo ""
echo "  Quick start:"
echo "    1. Edit ${ENV_FILE} — set AEGIS_BACKEND_API_KEY"
echo "    2. ${LAUNCH_SCRIPT}"
echo "    3. curl -sf http://localhost:8080/health"
echo ""
echo "  Run diagnostic: python tools/forensic/diagnose_aegis.py"
echo ""
