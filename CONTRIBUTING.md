<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Contributing to Aegis Latent Core

Thank you for your interest in contributing. This project is maintained by its
sole copyright holder, **Juan Luna** (`juan.c.luna04@gmail.com`), and is
distributed under a **dual-licensing model**: the GNU Affero General Public
License v3 (AGPLv3) for open-source use, and a separate Proprietary Commercial
License for closed-source and enterprise use (see [`LICENSE`](LICENSE) and
[`COMMERCIAL.md`](COMMERCIAL.md)).

Because the project is dual-licensed, **every contribution must be made under
terms that allow the maintainer to continue offering the software under both
licenses.** The framework below — a Developer Certificate of Origin (DCO) plus a
lightweight Contributor License Agreement (CLA) — exists to make that possible
while keeping the contribution process fast and low-friction.

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
to license it under both the AGPLv3 and the Proprietary Commercial License.

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

The DCO certifies *provenance*. Because this project is **dual-licensed**, we
additionally require a lightweight **copyright license grant** so the maintainer
can keep offering the software commercially. By submitting a contribution (a pull
request, patch, or any other work) to this repository, **you agree to the
following on a forward-looking basis for that contribution:**

### 3.1 Grant of copyright license

You hereby grant to **Juan Luna** (the "Maintainer") a **perpetual, worldwide,
non-exclusive, royalty-free, irrevocable, and sublicensable** license to
reproduce, prepare derivative works of, publicly display, publicly perform,
sublicense, and distribute your contribution and such derivative works.

### 3.2 Right to relicense and to dual-license

You agree that the Maintainer may license and distribute your contribution under
**any license terms**, including:

- the GNU Affero General Public License v3 (AGPLv3); **and**
- one or more **proprietary commercial licenses**, on terms set solely by the
  Maintainer, including the right to **sublicense and to sell** the software as
  part of a closed-source or commercial offering,

**without any obligation of accounting, royalty, or further consent to you.**

### 3.3 Grant of patent license

You grant the Maintainer and all recipients of the software a perpetual,
worldwide, non-exclusive, royalty-free, irrevocable patent license to make, have
made, use, offer to sell, sell, import, and otherwise transfer your contribution,
where such license applies only to those patent claims licensable by you that are
necessarily infringed by your contribution alone or by combination of your
contribution with the project.

### 3.4 You retain your ownership

This is a **license grant, not an assignment**. You retain copyright ownership of
your contribution and may use it elsewhere. The CLA does not transfer title; it
guarantees the Maintainer the rights needed to operate the dual-license model.

### 3.5 Your representations

By contributing, you represent that:

1. Each contribution is your original creation, or you have sufficient rights to
   submit it under these terms;
2. Your contribution does not knowingly violate any third party's intellectual
   property rights; and
3. If your employer has rights to intellectual property you create, you have
   received permission to make the contribution on behalf of that employer, or
   your employer has waived such rights for this contribution.

### 3.6 Scope

This CLA applies to **contributions you submit after the publication of this
document**. It is forward-looking. It does not retroactively change the terms of
any contribution already merged; as stated in §1, all existing work is already
solely owned by the Maintainer.

### 3.7 How you accept

You accept this CLA by either:

- including the DCO `Signed-off-by` line **and** the following line in your pull
  request description:

  ```
  I have read CONTRIBUTING.md and I agree to the Contributor License Agreement.
  ```

- or replying `I agree to the CLA` on your pull request when asked by a
  maintainer.

For substantial or corporate contributions, the Maintainer may request a signed
copy of the CLA by email before merging.

---

## 4. Development workflow

1. **Fork** the repository and create a feature branch.
2. **Install** the dev environment:
   ```bash
   python -m venv .venv && source .venv/bin/activate
   pip install -e ".[dev]"
   ```
3. **Make your change.** New source files must carry the standard header:
   ```bash
   python scripts/apply_license_headers.py
   ```
4. **Test and lint** — all must pass:
   ```bash
   pytest tests/ -x -q
   mypy aegis/ --ignore-missing-imports
   ruff check aegis/
   # Rust changes:
   cargo test --manifest-path aegis_rust_v2/Cargo.toml --all-features
   ```
5. **Document new claims.** Any new performance claim must ship with a benchmark
   in `benchmarks/` and a results entry in `docs/BENCHMARKS.md`. Any change to the
   audit chain or WAL must pass `tests/test_security_fixes.py`.
6. **Sign off and open a PR** (`git commit -s`), including the CLA acceptance line
   from §3.7.

---

## 5. License of your contributions

Unless explicitly stated otherwise in writing, your contributions are accepted
under the terms above: licensed to the Maintainer per the CLA (§3) and
distributable by the project under AGPLv3 and the Proprietary Commercial License.

---

**Questions about contributing or licensing:** `juan.c.luna04@gmail.com`
