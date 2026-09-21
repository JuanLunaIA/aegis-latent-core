# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Benchmark harnesses.

Every harness in this package prints a provenance banner before its numbers, via
:func:`print_provenance`. The banner exists because the figures these modules
produce are observations on one host on one date: ``docs/benchmarks/BENCHMARK_METHOD.md``
states that no RPS figure is claimed for any environment, and a harness banner that
reads as an absolute statement contradicts the repository's own citation rules
(AUD-26).
"""

from __future__ import annotations

import os
import platform
from datetime import UTC, datetime

#: The sentence every harness's banner carries. Kept as a constant so the gate
#: (``tests/test_benchmark_claim_labels.py``) can assert what readers were told,
#: not just that a banner was printed.
PROVENANCE_NOTE = (
    "Observations on this host and date. Not a capacity, latency or "
    "production-readiness claim for any environment. "
    'docs/benchmarks/BENCHMARK_METHOD.md: "No RPS figure is claimed for any '
    'environment." Cite the retained artifact, not this output.'
)


def print_provenance(harness: str) -> None:
    """Print the host/date/limits banner that must precede a harness's numbers."""
    print("=" * 78)
    print(f"{harness} — provenance")
    print(
        f"  host      : {platform.node() or 'unknown'} ({platform.machine()}, {platform.system()})"
    )
    print(f"  cpus      : {os.cpu_count()}")
    print(f"  python    : {platform.python_version()}")
    print(f"  generated : {datetime.now(UTC).replace(microsecond=0).isoformat()}")
    print(f"  caveat    : {PROVENANCE_NOTE}")
    print("=" * 78)
