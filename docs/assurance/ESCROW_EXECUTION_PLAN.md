<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Escrow Execution Plan

**Audience:** the owner executing `REG-H03`, and the escrow agent's verification team.
**Scope:** the steps from term sheet to a verified deposit, and the tool that produces the deposit manifest for the repository part. It serves milestone `M9` (agreement executed, first deposit verified, 2027-03-31).
**Boundary:** a plan and a manifest builder. No agent is engaged, no agreement is signed and no deposit has been made. A deposit that nobody rebuilt is a box of files.

## Steps

| # | Step | Who | Evidence |
| --- | --- | --- | --- |
| 1 | Choose an agent; send the [term sheet](../legal/ESCROW_TERM_SHEET.md) | Owner | Agent's reply |
| 2 | Counsel compares the agent's standard agreement to the term sheet | Counsel | Written notes |
| 3 | Execute the tri-party agreement | Owner, buyer, agent | Signed agreement |
| 4 | Prepare the deposit per `docs/MAINTAINER_HANDBOOK.md` §7 | Owner | Bundle, wheels, images, checksums, access list |
| 5 | Build the manifest for the tagged commit and keep it with the deposit | Owner | `manifest.json`, tree digest |
| 6 | Agent rebuilds a working artifact from the deposit | Agent | Verification report |
| 7 | Record the result in [Assurance Status](ASSURANCE_STATUS.md) | Owner | Report path |

## The manifest for the repository part

```bash
python tools/assurance/escrow_manifest.py build --ref v5.0.1 --out manifest.json
git archive v5.0.1 | tar -x -C restored/
python tools/assurance/escrow_manifest.py verify manifest.json restored/
```

`build` lists every tracked file at the ref with its size and SHA-256, one digest over the list, and the deposit category it falls under. It refuses if a tracked path looks like key material. For `v5.0.1` it recorded 1,319 files, 24,504,107 bytes and tree digest `37a4e2169a97ec80c062eaf1de72b4cbb1b8776c0bac0ec50d35acf868f8b2b6` at commit `46db6c0c65582bbb46137fd14182a976274b34e8` (read 2026-09-29); an unaltered `git archive` restore verified with 0 problems and a changed file was reported.

This covers only the tracked source. The manifest lists what it does not cover: the vendored wheels, the base images, the release checksums and provenance as read back, and the access list and key-custody procedure.

## What must never be deposited

The Ed25519 licence-signing private key, any customer key material and any secret. The custody **procedure** is deposited; the key is not. The tool's deny list and `tests/test_assurance_tools.py` guard the repository part.

## What the agent's rebuild should do

Follow the handbook's verification list: restore the bundle, confirm the tag with `scripts/verify_release_tag.sh`, install from the vendored wheels with `--no-index --require-hashes`, run the test gates, build the image and run the smoke test. Ask the agent to report each step, not only the outcome.

## Closing

`REG-H03` closes only when the agreement is signed and a verified deposit exists. Escrow reduces artifact risk; it does not replace a second maintainer (`REG-H05`).
