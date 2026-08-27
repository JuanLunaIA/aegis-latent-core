# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis_server — Enterprise-grade LLM inference governance layer.

Sub-packages:
    storage    — Pluggable async persistence backends (SQLite, PostgreSQL, DynamoDB).
    crypto     — Signing providers (HMAC-SHA256, HashiCorp Vault Transit ML-DSA).
    compliance — SOC2 / HIPAA cryptographically sealed export bundles.
"""

from aegis import __version__

__all__ = ["__version__"]
