# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Package the verifier kit as one zip an external auditor can run without this repository.

    python tools/sales/build_verifier_kit.py --out aegis-verifier-kit.zip

The kit holds ``prove_it.py``, the three synthetic fixtures, a README and a
``SHA256SUMS`` over all of them. The zip is deterministic (fixed timestamps and order),
so two builds of one commit are byte-identical. It is a build output, not committed.
An auditor still installs the SDK: ``pip install aegis-latent-sdk``.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
KIT = ROOT / "tools" / "sales" / "prove_it"
FILES = ("prove_it.py", "record.json", "record_tampered.json", "TRUSTED_ROOT.txt")
README = """Aegis verifier kit
==================

Install the SDK, then run the demo (no network call is made):

    pip install aegis-latent-sdk
    python prove_it.py --demo

It accepts one synthetic record and rejects an altered record and an unrelated root.
To check a record you were given:

    python prove_it.py verify RECORD.json TRUSTED_ROOT

A pass establishes inclusion under the root you supplied and nothing else. The root
must reach you by a path the person who gave you the record does not control.
Check the files against SHA256SUMS before you rely on them: sha256sum -c SHA256SUMS
"""
STAMP = (2026, 1, 1, 0, 0, 0)


def build(out: Path) -> str:
    contents: dict[str, bytes] = {name: (KIT / name).read_bytes() for name in FILES}
    contents["README.txt"] = README.encode()
    sums = "".join(
        f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in sorted(contents.items())
    )
    contents["SHA256SUMS"] = sums.encode()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(contents):
            info = zipfile.ZipInfo(name, STAMP)
            info.external_attr = 0o644 << 16
            archive.writestr(info, contents[name])
    return hashlib.sha256(out.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    print(f"{build(args.out)}  {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
