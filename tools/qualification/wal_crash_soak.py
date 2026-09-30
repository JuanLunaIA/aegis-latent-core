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
allowed. A kill that lands inside a write leaves a partial last line. Replay latches
``wal_corrupt`` on it and the gateway answers 503 until ``tools/wal_repair.py`` removes it,
because appending onto an unreadable prefix produces records that can never be replayed. The
driver does the same between rounds: it applies that supported repair, counts it, and the
worker refuses to commit on a ledger that is not healthy.

**What this does not test:** SIGKILL ends the process but leaves the operating
system's page cache intact, so it exercises replay and torn-tail handling, not the
storage stack. A real power-loss test needs the target hardware or a VM whose disk is
cut mid-write, and the ``--wal`` path on that storage. A 30-day soak is ``--hours 720``
on that host; this tool runs whatever length it is given and reports it.

Exit 0 when no acknowledged commit was lost in any round, 1 otherwise.
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
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
WORKER_REFUSED = 3  # exit status of a worker that found the ledger unhealthy


def worker(wal: str, start: int) -> None:
    """Commit forever; acknowledge each id on stdout only after its commit returned."""
    from aegis.core.crypto_audit import CryptographicAuditLedger

    ledger = CryptographicAuditLedger(wal, signing_key=KEY)
    if ledger._fault_state != "healthy":
        # The gateway answers 503 here; a worker that carried on would acknowledge
        # commits that a later replay cannot reach.
        raise SystemExit(WORKER_REFUSED)
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


def heal_torn_tail(wal: str) -> bool:
    """Apply the supported repair (``tools/wal_repair.py --apply``) to a torn trailing record.

    True when the repair succeeded. False when the tool refused, which it does for any damage
    that is not a single unparseable last line: that is corruption, not a torn write.
    """
    spec = importlib.util.spec_from_file_location("wal_repair_tool", ROOT / "tools/wal_repair.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("wal_crash_soak: cannot load tools/wal_repair.py")
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    backup = Path(wal + ".torn.bak")  # one file, overwritten: a long soak must not fill the disk
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        code: int = tool.repair(Path(wal), apply=True, backup=backup)
    return code == 0


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
    if proc.returncode == WORKER_REFUSED:
        raise SystemExit("wal_crash_soak: FAIL (the worker found an unhealthy ledger and refused)")
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
        torn = ledger._fault_state == "wal_corrupt"
        healed = True
        if torn:
            del ledger  # release the single-writer lock before the file is rewritten
            healed = heal_torn_tail(wal)
            ledger = CryptographicAuditLedger(wal, signing_key=KEY)
        valid, bad_index = ledger.verify_integrity()
        valid = valid and healed and ledger._fault_state == "healthy"
        present = _ids(ledger)
        missing = sorted(acknowledged - set(present))
        duplicates = len(present) - len(set(present))
        lost_total += len(missing)
        rounds.append(
            {
                "round": n, "acknowledged_this_round": len(acked), "chain_nodes": len(ledger.chain),
                "integrity_valid": valid, "first_bad_index": bad_index,
                "acknowledged_missing": len(missing), "duplicates": duplicates,
                "torn_tail_repaired": torn and healed,
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
        "torn_tails_repaired": sum(1 for r in rounds if r["torn_tail_repaired"]),
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
