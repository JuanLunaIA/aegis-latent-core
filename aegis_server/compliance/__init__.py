# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
"""
aegis_server.compliance — SOC2 Type II / HIPAA audit export sub-package.

Public API::

    from aegis_server.compliance import ComplianceExporter, ExportParams, ExportResult

    exporter = ComplianceExporter(storage=..., signer=..., export_dir="./exports")
    result = await exporter.export(ExportParams(from_offset=0, limit=10_000, tenant_id=None))
"""

from aegis_server.compliance.exporter import (
    ComplianceExporter,
    ExportParams,
    ExportResult,
)

__all__ = ["ComplianceExporter", "ExportParams", "ExportResult"]
