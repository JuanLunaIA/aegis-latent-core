#!/usr/bin/env python3
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Coverage-guided fuzzing of the PHI de-identifier.

    python tests/redteam/fuzz/fuzz_phi_deidentifier.py -atheris_runs=200000

The de-identifier runs over model output — text an attacker influences by
asking for it — and it sits inside the evidence path, so an unhandled exception
there is not a bad redaction, it is a failed request. Two properties are
asserted on every input:

1. **It never raises.** Any exception escaping `scrub` is a crash finding.
2. **Redaction is idempotent.** Scrubbing already-scrubbed text must not find
   new PHI. If it does, the redaction markers themselves are matching a
   pattern, which means output is being re-redacted and the number of hits an
   audit record reports depends on how many times the text was processed.

The corpus is decoded as UTF-8 with surrogate escaping so the fuzzer explores
malformed byte sequences too — the boundary a proxy actually sees.

`atheris` is a development-only dependency and is deliberately absent from
`requirements.lock`; this harness is not imported by the test suite.
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from aegis.core.phi_deidentifier import PHIDeidentifier

_DEIDENTIFIER = PHIDeidentifier()

#: Emitted in place of detected PHI. Scrubbing output that already contains
#: these must be a fixed point.
_MARKER = "[REDACTED:"


def test_one_input(data: bytes) -> None:
    text = data.decode("utf-8", errors="surrogateescape")

    result = _DEIDENTIFIER.scrub(text)

    # The audit record and the text must agree: a hit count that does not
    # correspond to the redacted output is a misleading audit trail.
    if result.total_hits and _MARKER not in result.text:
        raise AssertionError(
            f"scrub reported {result.total_hits} hits but emitted no marker: {text!r}"
        )

    second = _DEIDENTIFIER.scrub(result.text)
    if second.total_hits:
        raise AssertionError(
            "redaction is not idempotent: rescrubbing found "
            f"{second.total_hits} further hits in {result.text!r} (from {text!r})"
        )


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
