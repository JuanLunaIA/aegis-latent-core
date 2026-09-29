# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Kill a committing process again and again and check that no acknowledged commit is lost.

    python tools/qualification/wal_crash_soak.py --rounds 20 [--wal PATH] [--json OUT]
    python tools/qualification/wal_crash_soak.py --hours 720 --wal /mnt/target/aegis.wal.jsonl

Each round starts a worker that commits evidence records to one WAL and prints a
record's id only *after* its commit returned. The driver kills the worker with
SIGKILL at a random moment, reopens the ledger (which replays the WAL), and checks:

1. the chain verifies (``verify_integrity``);
2. every id the worker acknowledged is present (an acknowledged commit is never lost);
3. the recovered chain has no duplicate and no hole among acknowledged ids.

A record that was in flight when the process died may be present or absent; both are
allowed. **What this does not test:** SIGKILL ends the process but leaves the operating
system's page cache intact, so it exercises replay and torn-tail handling, not the
storage stack. A real power-loss test needs the target hardware or a VM whose disk is
cut mid-write, and the ``--wal`` path on that storage. A 30-day soak is ``--hours 720``
on that host; this tool runs whatever length it is given and reports it.

Exit 0 when no acknowledged commit was lost in any round, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
KEY = "soak-signing-key-0123456789abcdef0123456789abcdef"


def worker(wal: str, start: int) -> None:
    """Commit forever; acknowledge each id on stdout only after its commit returned."""
    from aegis.core.crypto_audit import CryptographicAuditLedger

    ledger = CryptographicAuditLedger(wal, signing_key=KEY)
    index = start
    while True:
        ledger.commit_forensic(
            state_id=f"soak-{index:09d}", request_bytes=f"request {index}".encode()
        )
        sys.stdout.write(f"{index}\n")
        sys.stdout.flush()
        index += 1


def _ids(ledger: Any) -> list[int]:
    out: list[int] = []
    for node in ledger.chain:
        state = str(getattr(node, "state_id", ""))
        if state.startswith("soak-") and state[5:].isdigit():
            out.append(int(state[5:]))
    return out


def run_round(wal: str, start: int, seconds: float) -> tuple[list[int], int]:
    proc = subprocess.Popen(  # noqa: S603  # nosec B603 - this interpreter and this file, shell=False
        [sys.executable, str(Path(__file__).resolve()), "--worker", wal, str(start)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
    )
    time.sleep(seconds)
    proc.send_signal(signal.SIGKILL)
    assert proc.stdout is not None
    raw = proc.stdout.read().decode().split()
    proc.wait()
    acked = [int(x) for x in raw if x.isdigit()]
    return acked, (max(acked) + 1 if acked else start)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rounds", type=int, default=20)
    parser.add_argument("--hours", type=float, default=None, help="run rounds until this long")
    parser.add_argument("--wal", type=Path, default=None)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--json", type=Path, default=None)
    parser.add_argument("--worker", nargs=2, metavar=("WAL", "START"), default=None)
    args = parser.parse_args(argv)
    if args.worker:
        worker(args.worker[0], int(args.worker[1]))
        return 0

    from aegis.core.crypto_audit import CryptographicAuditLedger

    rng = random.Random(args.seed)  # noqa: S311  # nosec B311 - kill timing, not security
    wal = str(args.wal or Path(tempfile.mkdtemp(prefix="aegis_soak_")) / "wal.jsonl")
    started = time.monotonic()
    deadline = started + args.hours * 3600 if args.hours else None
    acknowledged: set[int] = set()
    next_index = 0
    rounds: list[dict[str, Any]] = []
    lost_total = 0
    n = 0
    while (deadline is None and n < args.rounds) or (
        deadline is not None and time.monotonic() < deadline
    ):
        n += 1
        acked, next_index = run_round(wal, next_index, rng.uniform(0.6, 2.0))
        acknowledged.update(acked)
        ledger = CryptographicAuditLedger(wal, signing_key=KEY)
        valid, bad_index = ledger.verify_integrity()
        present = _ids(ledger)
        missing = sorted(acknowledged - set(present))
        duplicates = len(present) - len(set(present))
        lost_total += len(missing)
        rounds.append(
            {
                "round": n, "acknowledged_this_round": len(acked), "chain_nodes": len(ledger.chain),
                "integrity_valid": valid, "first_bad_index": bad_index,
                "acknowledged_missing": len(missing), "duplicates": duplicates,
            }
        )  # fmt: skip
        print(
            f"round {n:>3}: acked {len(acked):>5}  integrity {valid}  missing {len(missing)}  dup {duplicates}"
        )
        if not valid or missing or duplicates:
            break
        del ledger
        next_index = max(next_index, max(present, default=-1) + 1)
    report = {
        "rounds": len(rounds), "elapsed_seconds": round(time.monotonic() - started, 1),
        "acknowledged_total": len(acknowledged), "acknowledged_lost": lost_total,
        "all_rounds_valid": all(r["integrity_valid"] for r in rounds),
        "kill": "SIGKILL of the committing process (not a power cut)", "wal": wal,
        "seed": args.seed, "detail": rounds,
    }  # fmt: skip
    if args.json:
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    ok = (
        lost_total == 0 and report["all_rounds_valid"] and all(r["duplicates"] == 0 for r in rounds)
    )
    print(
        f"wal_crash_soak: {'PASS' if ok else 'FAIL'} ({report['rounds']} rounds, {len(acknowledged)} acknowledged commits, {lost_total} lost)"
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
