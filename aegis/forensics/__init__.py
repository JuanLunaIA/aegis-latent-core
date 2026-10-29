"""Dependency-free forensic query primitives."""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.

from aegis.forensics.search import (
    DEFAULT_PAGE_LIMIT,
    MAX_PAGE_LIMIT,
    AuditNodeLike,
    ForensicSearchQuery,
    SearchOrder,
    SearchPage,
    search_retained_nodes,
)

__all__ = [
    "DEFAULT_PAGE_LIMIT",
    "MAX_PAGE_LIMIT",
    "AuditNodeLike",
    "ForensicSearchQuery",
    "SearchOrder",
    "SearchPage",
    "search_retained_nodes",
]
