# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import subprocess
import time
from array import array
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path


def git_head(root: Path) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()


def online_two_sided_p_value(t_statistic: float) -> float:
    return math.erfc(abs(t_statistic) / math.sqrt(2.0))


def welch_statistic(first: array, second: array) -> tuple[float, int, float, float]:
    def mean_variance(values: array) -> tuple[float, float]:
        count = 0
        mean = 0.0
        m2 = 0.0
        for value in values:
            count += 1
            delta = value - mean
            mean += delta / count
            m2 += delta * (value - mean)
        return mean, m2 / max(1, count - 1)

    mean_a, var_a = mean_variance(first)
    mean_b, var_b = mean_variance(second)
    n_a, n_b = len(first), len(second)
    standard_error = math.sqrt((var_a / n_a) + (var_b / n_b))
    t_statistic = (mean_a - mean_b) / standard_error if standard_error else 0.0
    numerator = ((var_a / n_a) + (var_b / n_b)) ** 2
    denominator = ((var_a / n_a) ** 2 / max(1, n_a - 1)) + ((var_b / n_b) ** 2 / max(1, n_b - 1))
    degrees_of_freedom = int(max(1.0, numerator / denominator)) if denominator else 1
    return t_statistic, degrees_of_freedom, mean_a, mean_b


def cpu_affinity() -> list[int] | None:
    if hasattr(os, "sched_getaffinity"):
        return sorted(os.sched_getaffinity(0))
    return None


def cpu_model() -> str | None:
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        return None
    return None


def measure(
    operation: str,
    samples: int,
    warmup: int,
    sign: Callable[[bytes], bytes],
    verify: Callable[[bytes, bytes, bytes], bool],
    public_key: bytes,
) -> tuple[array, array, bool]:
    fixed = b"A" * 32
    variable_pool = [
        hashlib.sha256(f"aegis-pqc-timing-{index}".encode()).digest() for index in range(1024)
    ]
    if operation == "verify":
        # Keep the message constant and vary only valid signatures. This avoids
        # conflating message hashing with the verifier boundary.
        variable_pool = [fixed] * len(variable_pool)
    fixed_signature = sign(fixed)
    variable_signatures = [sign(message) for message in variable_pool]
    for index in range(warmup):
        message = fixed if index % 2 == 0 else variable_pool[index % len(variable_pool)]
        signature = (
            fixed_signature
            if index % 2 == 0
            else variable_signatures[index % len(variable_signatures)]
        )
        if operation == "sign":
            sign(message)
        else:
            verify(message, signature, public_key)
    first = array("d")
    second = array("d")
    all_valid = True
    for index in range(samples):
        is_variable = index % 2 == 1
        message = variable_pool[index % len(variable_pool)] if is_variable else fixed
        signature = (
            variable_signatures[index % len(variable_signatures)]
            if is_variable
            else fixed_signature
        )
        started = time.perf_counter_ns()
        if operation == "sign":
            sign(message)
        else:
            all_valid = bool(verify(message, signature, public_key)) and all_valid
        elapsed_ns = float(time.perf_counter_ns() - started)
        (second if is_variable else first).append(elapsed_ns)
    return first, second, all_valid


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run an isolated ML-DSA timing leakage experiment."
    )
    parser.add_argument("--operation", choices=("sign", "verify", "both"), default="both")
    parser.add_argument("--samples", type=int, default=1_000_000)
    parser.add_argument("--warmup", type=int, default=10_000)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--raw-output", type=Path, required=True)
    args = parser.parse_args()
    if args.samples < 1_000_000 or args.samples > 10_000_000 or args.samples % 2:
        raise ValueError("samples must be an even value between 1,000,000 and 10,000,000")
    if args.warmup < 0 or args.warmup > 1_000_000:
        raise ValueError("warmup must be between 0 and 1,000,000")
    root = Path(__file__).resolve().parents[2]
    report: dict[str, object] = {
        "schema": "aegis-pqc-timing-report-v1",
        "generated_at_utc": datetime.now(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "repository": "JuanLunaIA/aegis-latent-core",
        "commit_sha": git_head(root),
        "experiment": {
            "method": "two-class interleaved Welch timing test with normal-tail p-value",
            "operations_requested": args.operation,
            "samples_per_operation": args.samples,
            "samples_per_class": args.samples // 2,
            "warmup_per_operation": args.warmup,
            "message_length_bytes": 32,
            "variable_pool_size": 1024,
            "threshold": "p-value > 0.05 is non-detection only, not a constant-time proof",
        },
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "cpu_model": cpu_model(),
            "cpu_affinity": cpu_affinity(),
            "pid": os.getpid(),
        },
        "status": "UNVERIFIED",
        "results": {},
        "limitations": [
            "The harness measures the exposed Python-to-native boundary, including key/signature decode work performed by the current Rust binding.",
            "Normal-tail p-values are an experiment statistic and do not prove constant-time execution, algorithm conformance, or FIPS 140 validation.",
            "No claim is made about scheduler, cache, branch-predictor, compiler, microcode, hardware, or remote deployment behavior beyond this run.",
        ],
    }
    try:
        from aegis.core.pqc_signer import PQCSigner

        signer = PQCSigner(require_real=True)
    except Exception as exc:
        report["status"] = "UNAVAILABLE"
        report["backend_error_type"] = type(exc).__name__
        report["gate"] = {
            "passed": False,
            "reason": "real ML-DSA backend unavailable; no timing claim emitted",
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(json.dumps({"status": report["status"], "output": str(args.output)}, sort_keys=True))
        return 2

    operations = ("sign", "verify") if args.operation == "both" else (args.operation,)
    args.raw_output.parent.mkdir(parents=True, exist_ok=True)
    with args.raw_output.open("w", encoding="utf-8") as raw_handle:
        raw_handle.write(
            json.dumps(
                {
                    "schema": "aegis-pqc-timing-raw-v1",
                    "commit_sha": report["commit_sha"],
                    "note": "Raw nanosecond timings only; no signing keys or signatures are included.",
                },
                sort_keys=True,
            )
            + "\n"
        )
        for operation in operations:
            first, second, all_valid = measure(
                operation,
                args.samples,
                args.warmup,
                signer.sign,
                PQCSigner.verify,
                signer.public_key,
            )
            t_statistic, degrees_of_freedom, fixed_mean, variable_mean = welch_statistic(
                first, second
            )
            p_value = online_two_sided_p_value(t_statistic)
            report["results"][operation] = {
                "validity": all_valid,
                "fixed_mean_ns": fixed_mean,
                "variable_mean_ns": variable_mean,
                "delta_ns": variable_mean - fixed_mean,
                "t_statistic": t_statistic,
                "degrees_of_freedom": degrees_of_freedom,
                "p_value_normal_tail": p_value,
                "sample_count": len(first) + len(second),
                "raw_sample_count": len(first) + len(second),
                "non_detection_threshold_met": all_valid and p_value > 0.05,
            }
            for sample in first:
                raw_handle.write(
                    json.dumps(
                        {"operation": operation, "class": "fixed", "elapsed_ns": sample},
                        sort_keys=True,
                    )
                    + "\n"
                )
            for sample in second:
                raw_handle.write(
                    json.dumps(
                        {"operation": operation, "class": "variable", "elapsed_ns": sample},
                        sort_keys=True,
                    )
                    + "\n"
                )
    report["raw_samples"] = {
        "path": str(args.raw_output),
        "format": "JSONL with one timing per line after a metadata header",
        "sample_count_per_operation": args.samples,
    }
    results = report["results"]
    passed = all(item["non_detection_threshold_met"] for item in results.values())
    report["status"] = "MEASURED"
    report["gate"] = {
        "passed": passed,
        "meaning": "No statistically significant timing difference detected under this experiment; not a constant-time proof.",
        "human_review_required": True,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {"status": report["status"], "passed": passed, "output": str(args.output)},
            sort_keys=True,
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
