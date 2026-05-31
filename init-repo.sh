#!/usr/bin/env bash
# init-repo.sh — one-shot script to initialize the Git repository and push.
# Run once from the project root after cloning or extracting the tarball.
#
# Usage:
#   chmod +x init-repo.sh
#   REMOTE_URL=https://github.com/YOUR_ORG/aegis-latent-core.git ./init-repo.sh
#
# Prerequisites: git, python3>=3.11, maturin (for Rust .so build)

set -euo pipefail

REMOTE_URL="${REMOTE_URL:-}"
BRANCH="${BRANCH:-main}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[init]${NC} $*"; }
warn()  { echo -e "${YELLOW}[warn]${NC} $*"; }
die()   { echo -e "${RED}[error]${NC} $*" >&2; exit 1; }

# ── 0. Sanity checks ─────────────────────────────────────────────────────────
command -v git  >/dev/null 2>&1 || die "git not found"
command -v python3 >/dev/null 2>&1 || die "python3 not found"
[[ -f pyproject.toml ]] || die "Run this script from the project root (pyproject.toml not found)"

# ── 1. Verify no secrets in tree ─────────────────────────────────────────────
info "Scanning for potential secret leaks..."
# Patterns that should not appear in committed source
LEAK_PATTERNS='(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----)'
if grep -rP "$LEAK_PATTERNS" --include='*.py' --include='*.toml' --include='*.yml' \
       --include='*.yaml' --include='*.env' . 2>/dev/null | grep -v '.env.example'; then
  die "Potential secret found in source tree. Abort."
fi
info "No secrets detected."

# ── 2. Confirm .env is not tracked ───────────────────────────────────────────
if [[ -f .env ]]; then
  warn ".env file exists locally — confirm it is gitignored before proceeding."
  if git check-ignore -q .env 2>/dev/null; then
    info ".env is gitignored. Safe."
  else
    die ".env is NOT gitignored. Fix .gitignore first."
  fi
fi

# ── 3. Build Rust extension (optional, skip if maturin absent) ───────────────
if command -v maturin >/dev/null 2>&1; then
  info "Building aegis_rust_v2 extension..."
  (cd aegis_rust_v2 && maturin build --release 2>&1)
  info "Rust build complete."
else
  warn "maturin not found — skipping Rust extension build."
  warn "Install with: pip install maturin"
  warn "The .so will need to be built before running the proxy."
fi

# ── 4. Initialize git ────────────────────────────────────────────────────────
if [[ ! -d .git ]]; then
  info "Initializing git repository..."
  git init -b "$BRANCH"
else
  info "Git repo already initialized."
fi

# ── 5. Configure user if missing ─────────────────────────────────────────────
if ! git config user.email >/dev/null 2>&1; then
  warn "git user.email not configured. Set it before committing:"
  warn "  git config user.email 'you@example.com'"
  warn "  git config user.name 'Your Name'"
fi

# ── 6. Stage and commit ───────────────────────────────────────────────────────
info "Staging all files..."
git add -A
git status --short

info "Creating initial commit..."
git commit -m "chore: initial release — aegis-latent-core v2.0.0

Forensic telemetry proxy and Merkle audit chain for LLM inference pipelines.

- FastAPI OpenAI-compatible proxy with entropy analysis
- Merkle MMR chain-of-custody audit log
- PQC bindings (ML-DSA / ML-KEM) via aegis_rust_v2 (PyO3)
- WAF, mTLS, seccomp guard, rate limiter
- vLLM + HuggingFace integration plugins
- Helm chart, Docker Compose, GitHub Actions CI
- TLA+ formal specs for ledger immutability and session manager"

# ── 7. Add remote and push (optional) ────────────────────────────────────────
if [[ -n "$REMOTE_URL" ]]; then
  info "Adding remote origin: $REMOTE_URL"
  git remote add origin "$REMOTE_URL" 2>/dev/null \
    || git remote set-url origin "$REMOTE_URL"
  info "Pushing to $BRANCH..."
  git push -u origin "$BRANCH"
  info "Push complete."
else
  warn "REMOTE_URL not set — skipping push."
  warn "To push manually:"
  warn "  git remote add origin https://github.com/YOUR_ORG/aegis-latent-core.git"
  warn "  git push -u origin $BRANCH"
fi

info "Done. Repository is ready."
