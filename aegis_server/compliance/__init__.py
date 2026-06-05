# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
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
