# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
"""
aegis_server — Enterprise-grade LLM inference governance layer.

Sub-packages:
    storage    — Pluggable async persistence backends (SQLite, PostgreSQL, DynamoDB).
    crypto     — Signing providers (HMAC-SHA256, HashiCorp Vault Transit ML-DSA).
    compliance — SOC2 / HIPAA cryptographically sealed export bundles.
"""

from aegis import __version__

__all__ = ["__version__"]
