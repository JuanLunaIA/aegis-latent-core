<!--
Copyright (c) 2026 Juan Luna.
SPDX-License-Identifier: Apache-2.0
Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
-->

# Contributing to Aegis Latent Core

This document defines the contribution workflow, DCO sign-off, forward-looking CLA language, test expectations and public-claim review for Aegis. It is for prospective contributors, maintainers and organizations evaluating contribution rights. It is not legal advice.

**Last verified:** 2026-08-27 UTC
**Release baseline:** published release (`5.0.2`, Apache-2.0); latest published release `5.0.2`
**Source baseline:** `5.0.2` with fourteen synchronized anchors — the published Apache-2.0 release; the most recent published release is `5.0.1`, **published 2026-09-24 on every surface (PyPI `aegis-latent-core` `5.0.1` followed on 2026-09-26)**, read back the same day (`docs/RELEASE_STATUS.md` §1.0a). The previous release is `v5.0.0`, published 2026-09-16 on every surface except PyPI `aegis-latent-core` (see `docs/RELEASE_STATUS.md` §1.0); `v4.1.2` was the last version published on every surface before `5.0.1` completed the set on 2026-09-26, whose publication was read back on 2026-09-04 and is recorded in `docs/RELEASE_STATUS.md` §1.1
**Historical external baseline:** signed annotated `v4.0.2` tag at `a6eb58dcc03f8b638c8f3e35f0300f5443a926ca`, with GitHub Release and GHCR gateway/dashboard images read back on 2026-09-02; before it, lightweight `v4.0.1` at `6469904380218584ae0b5221334bc9a46500f5ba` with failed tag workflows; PyPI/npm observed at `4.0.0` without attributed provenance

Thank you for your interest in contributing. This project is maintained by its
sole copyright holder, **Juan Luna** (`juan.c.luna04@gmail.com`). From
version `5.0.2` the source is licensed under the **Apache License, Version 2.0**
(see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE)). Releases up to and including
`5.0.1` were published under the GNU Affero General Public License v3 (AGPLv3)
or a separate commercial licence; those published artifacts keep the terms they
were published under (see
[`docs/legal/LICENSE_TRANSITION_5.0.2.md`](docs/legal/LICENSE_TRANSITION_5.0.2.md)).

Under Section 5 of the Apache License, a contribution you intentionally submit
is licensed under the same Apache-2.0 terms unless you state otherwise in
writing. The framework below — a Developer Certificate of Origin (DCO) plus a
lightweight Contributor License Agreement (CLA) — records provenance and keeps
the maintainer able to keep maintaining and releasing the project, while keeping
the contribution process fast and low-friction.

> **Not legal advice.** This document describes the contribution terms for this
> repository. It is not legal advice. If you are contributing on behalf of an
> employer or any third party, obtain the appropriate authorization first.

---

## 1. Ownership of the existing codebase

All source code, documentation, build tooling, and other materials currently in
this repository were authored by Juan Luna (including work produced with
AI-assisted tooling operated by Juan Luna). To the maintainer's knowledge there
are **no third-party human contributions** in the project history. Accordingly,
Juan Luna is the **sole copyright holder** of the existing work, and is entitled
to license it under the Apache License, Version 2.0 (and was entitled to license
it under the AGPLv3 and a commercial licence for the releases published before
`5.0.2`).

This section is a factual statement about the current state of the repository.
It does not, and cannot, retroactively alter the terms under which any past
third-party contribution (if one were ever identified) was actually submitted.
Should any prior third-party contribution come to light, it will be handled
individually — relicensed with the contributor's explicit agreement, replaced,
or removed.

---

## 2. Developer Certificate of Origin (DCO)

Every commit must be signed off under the
[Developer Certificate of Origin 1.1](https://developercertificate.org/). By
adding a `Signed-off-by` line to your commit, you certify the following:

> **Developer Certificate of Origin — Version 1.1**
>
> By making a contribution to this project, I certify that:
>
> (a) The contribution was created in whole or in part by me and I have the
> right to submit it under the open source license indicated in the file; or
>
> (b) The contribution is based upon previous work that, to the best of my
> knowledge, is covered under an appropriate open source license and I have the
> right under that license to submit that work with modifications, whether
> created in whole or in part by me, under the same open source license (unless
> I am permitted to submit under a different license), as indicated in the file; or
>
> (c) The contribution was provided directly to me by some other person who
> certified (a), (b) or (c) and I have not modified it.
>
> (d) I understand and agree that this project and the contribution are public
> and that a record of the contribution (including all personal information I
> submit with it, including my sign-off) is maintained indefinitely and may be
> redistributed consistent with this project or the open source license(s)
> involved.

Add the sign-off automatically with:

```bash
git commit -s -m "your message"
```

This appends:

```
Signed-off-by: Your Name <your.email@example.com>
```

The name and email must be real and must match the commit author.

---

## 3. Contributor License Agreement (CLA)

The canonical, full Contributor License Agreement is [`CLA.md`](CLA.md). It
contains the copyright and patent grants, ownership preservation, contributor
and employer representations, third-party and AI-assisted material rules,
security and privacy boundaries, acceptance protocol, corporate acceptance
block, termination terms, and legal limitations.

The CLA is forward-looking: it applies to Contributions intentionally submitted
after the published CLA version is accepted. It does not retroactively change
the terms of an earlier contribution or an artifact already distributed under
its applicable licence. The current Project release is `5.0.2` under
Apache-2.0. The CLA does not create a commercial licence, compensation right,
merge obligation, support commitment, certification, or warranty.

The DCO and CLA serve different purposes:

- The **DCO** records provenance and the signer’s right to submit the work.
- The **CLA** grants the Maintainer the copyright and patent rights needed to
  maintain, distribute, and lawfully evolve the Project.

Unless the Maintainer approves another written method, contributors must provide
both a `Signed-off-by` line and the explicit CLA acceptance statement described
in [`CLA.md` §10](CLA.md#10-submission-procedure-and-acceptance-record). A CLA
service, pull-request record, or signed counterpart may be used as the durable
acceptance record. A pull-request comment is not a substitute for the configured
CLA service unless the Maintainer accepts that method for the repository.

## 4. Development workflow

1. **Fork** the repository and create a feature branch.
2. **Install** the dev environment:
   ```bash
   python3 -m venv .venv && source .venv/bin/activate
   python -m pip install -e ".[dev]"
   ```
   CI currently resolves the development extras from `pyproject.toml`; they are minimum-version ranges, not a hash-locked test-toolchain snapshot. For runtime-only reproduction, install `requirements.lock` with `--require-hashes` and then install the source with `python -m pip install --no-deps -e .`.
3. **Make your change.** New source files must carry the standard header:
   ```bash
   python scripts/apply_license_headers.py
   ```
4. **Test and lint** — all must pass:
   ```bash
   pytest tests/ -x -q
   mypy --config-file=mypy-ci.ini \
     aegis/config.py aegis/auth/apikey.py aegis/auth/principal.py \
     aegis/auth/oidc.py aegis/auth/mtls.py aegis/anchoring/rfc3161.py \
     aegis/core/mmr.py aegis/core/crypto_audit.py aegis/core/forensic.py \
     aegis/core/ratelimiter.py aegis/core/normalization.py \
     aegis/core/session_manager.py aegis/core/moe_monitor.py \
     aegis/core/leak_detector.py aegis/core/seccomp_guard.py \
     aegis/core/lsm_guard.py aegis/core/math_utils.py aegis/core/telemetry.py \
     aegis/proxy/waf.py aegis/proxy/schemas.py aegis/proxy/forwarder.py \
     aegis/proxy/streaming.py aegis/proxy/audit_api.py \
     aegis/proxy/dependencies.py aegis/proxy/rate_limiter.py \
     aegis/storage/s3_worm.py aegis/storage/segment_manifest.py \
     aegis/telemetry/events.py aegis/telemetry/otel.py aegis/telemetry/siem.py
   ruff check aegis aegis_server integrations tests tools/visualizer tools/forensic tools/benchmarks tools/security benchmarks
   ruff format --check aegis aegis_server integrations tests tools/visualizer tools/forensic tools/benchmarks tools/security benchmarks
   # Rust changes:
   cargo test --manifest-path aegis_rust_v2/Cargo.toml --all-features

   # Changes under sdk/python/ (the CI `sdk-python` job also runs these):
   (cd sdk/python && ruff check src tests && mypy --config-file pyproject.toml && pytest -q)
   python -m build sdk/python

   # Changes under sdk/typescript/ (the CI `sdk-typescript` job also runs these):
   (cd sdk/typescript && npm ci --ignore-scripts && npm run check && npm audit --audit-level=high && npm pack --dry-run)

   # Changes under dashboard/ (the CI `dashboard` job also builds the local TS SDK first):
   (cd sdk/typescript && npm ci --ignore-scripts && npm run build)
   (cd dashboard && npm ci --ignore-scripts && npm run typecheck && npm test && npm run build && npm audit --audit-level=high)
   ```

   Run only the language/component blocks affected by the change locally; CI executes all three jobs independently. Commit the relevant lockfile changes when dependencies change, and do not bypass tests, type checks, production builds, package dry-runs, or high-severity audits.
5. **Document new claims.** Any new performance claim must ship with a benchmark
   in `benchmarks/` and a results entry in `docs/BENCHMARKS.md`. Any change to the
   audit chain or WAL must pass `tests/test_security_fixes.py`.
6. **Sign off and open a PR** (`git commit -s`), including the CLA acceptance record
   from [`CLA.md`](CLA.md).
7. **Run documentation QA** when public claims, paths, benchmarks, or buyer language change:
   ```bash
   python tools/docs/verify_documentation.py --root .
   ```

---

## 5. License of your contributions

Unless explicitly stated otherwise in writing, your contributions are accepted
under the terms above: licensed to the Maintainer per the CLA (§3) and
distributable by the project under the Apache License, Version 2.0 (Section 5 of
that License: inbound equals outbound). Section 6 of the License grants no right
to use the project's name or marks; the CLA does not either.

---

**Questions about contributing or licensing:** `juan.c.luna04@gmail.com`

## Related documents

- [`CLA.md`](CLA.md) — canonical Contributor License Agreement
- [`README.md`](README.md)
- [`SECURITY.md`](SECURITY.md)
- [`COMMERCIAL.md`](COMMERCIAL.md)
- [`docs/legal/LICENSE_TRANSITION_5.0.2.md`](docs/legal/LICENSE_TRANSITION_5.0.2.md)
- [`docs/CLAIMS_MATRIX.md`](docs/CLAIMS_MATRIX.md)
- [`docs/DEVELOPER_QUICKSTART.md`](docs/DEVELOPER_QUICKSTART.md)
- [`tools/docs/verify_documentation.py`](tools/docs/verify_documentation.py)
