# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Connectors that carry Aegis evidence into systems an enterprise already runs.

Each connector is optional and imported on demand, so a dependency that is not
installed costs nothing until the connector is used. None of them is part of
the evidence path: a connector that fails **must not** be able to fail a
governed request, because a SIEM outage is not an evidence outage.

    aegis.connectors.siem.splunk_hec        -> Splunk HTTP Event Collector
    aegis.connectors.lakehouse.parquet_exporter -> Parquet for a lakehouse
    aegis.connectors.vault.transit_signer   -> HashiCorp Vault Transit signing

The authoritative record stays the JSONL WAL. Everything a connector emits is a
**copy**, and a copy in Splunk or a lakehouse is not the evidence — it is a
derivative whose fidelity depends on the connector, the transport and the
destination's own retention. Verification is always against the WAL.
"""

from __future__ import annotations

__all__: list[str] = []
