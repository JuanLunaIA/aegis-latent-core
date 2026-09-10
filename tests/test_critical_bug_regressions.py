# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Regressions for three defects that each failed in a quiet direction.

None of the three announced itself. Importing the proxy module took the WAL's
exclusive lock, so the documented factory failed against a writer that was the
importing process itself. Every commit signed under a fresh ML-DSA keypair
whose private half was discarded immediately, which reads as a post-quantum
signature and attributes nothing. And a new chain defaulted to the MMR
construction that admits leaf/interior type confusion.

Each test here reproduces the specific failure, so a revert makes it fail again
rather than merely leaving a behaviour unasserted.

Calls with side effects are assigned before being asserted on, never called
inside the ``assert`` itself (``python -O`` strips asserts; CodeQL flags this as
py/side-effect-in-assert).
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from aegis.core.crypto_audit import (
    MMR_NEW_CHAIN_DEFAULT_SCHEME,
    MMR_SCHEME_AUTO,
    CryptographicAuditLedger,
)
from aegis.core.mmr import HASH_SCHEME_V1, HASH_SCHEME_V2

REPO_ROOT = Path(__file__).resolve().parents[1]
SIGNING_KEY = "k" * 32


def _run_in_fresh_interpreter(source: str) -> subprocess.CompletedProcess[str]:
    """Run ``source`` in a new interpreter rooted at the repository.

    A subprocess is the point rather than an implementation detail: import-time
    side effects happen once per process, so a test sharing this process with
    every other test cannot observe them.
    """

    return subprocess.run(  # noqa: S603
        [sys.executable, "-c", textwrap.dedent(source)],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=180,
    )


class TestImportDoesNotCaptureTheWal:
    """P0-1: ``app = create_app()`` at import claimed the single-writer lock."""

    def test_factory_after_import_does_not_conflict(self) -> None:
        # The exact failure: import the module for any reason, then use the
        # documented factory. Before the fix this raised WalWriterConflictError
        # against a writer that was this very process.
        completed = _run_in_fresh_interpreter(
            """
            import aegis.proxy.app as module
            from aegis.proxy.app import create_proxy_app

            app = create_proxy_app()
            app.state.aegis.ledger.close()
            print("OK", type(app).__name__)
            """
        )
        assert completed.returncode == 0, completed.stderr[-2000:]
        assert "OK FastAPI" in completed.stdout

    def test_importing_the_module_builds_no_app(self) -> None:
        # Importing must stay cheap and side-effect-free. If the singleton were
        # populated at import, the lazy attribute would be decoration.
        completed = _run_in_fresh_interpreter(
            """
            import aegis.proxy.app as module

            print("SINGLETON", module._app_singleton is None)
            """
        )
        assert completed.returncode == 0, completed.stderr[-2000:]
        assert "SINGLETON True" in completed.stdout

    def test_the_app_attribute_still_resolves_and_is_a_singleton(self) -> None:
        # ``uvicorn.run("aegis.proxy.app:app")`` and ``from ... import app``
        # both go through the module __getattr__, so the ASGI entry point must
        # still work and must still be one app.
        completed = _run_in_fresh_interpreter(
            """
            import aegis.proxy.app as module

            first = module.app
            second = module.app
            from aegis.proxy.app import app as imported

            print("SAME", first is second is imported)
            print("DIR", "app" in dir(module))
            first.state.aegis.ledger.close()
            """
        )
        assert completed.returncode == 0, completed.stderr[-2000:]
        assert "SAME True" in completed.stdout
        assert "DIR True" in completed.stdout

    def test_an_unknown_attribute_still_raises_attribute_error(self) -> None:
        # A module __getattr__ that swallowed unknown names would turn every
        # typo into a silent None.
        completed = _run_in_fresh_interpreter(
            """
            import aegis.proxy.app as module

            try:
                module.no_such_attribute
            except AttributeError as exc:
                print("RAISED", "no_such_attribute" in str(exc))
            """
        )
        assert completed.returncode == 0, completed.stderr[-2000:]
        assert "RAISED True" in completed.stdout


class TestPqcIdentityIsPersistent:
    """P1-1: tier 2 minted a throwaway keypair for every signature."""

    def test_a_hundred_commits_share_one_public_key(self, tmp_path: Path) -> None:
        pytest.importorskip("aegis_rust")
        identity = tmp_path / "identity" / "ledger.pqc"
        with CryptographicAuditLedger(
            str(tmp_path / "a.wal"),
            signing_key=SIGNING_KEY,
            pqc_identity_path=str(identity),
        ) as ledger:
            keys = set()
            schemes = set()
            for index in range(100):
                node = ledger.commit_state(state_id=f"req-{index}", entropy=0.5, payload=b"payload")
                keys.add(node.public_key)
                schemes.add(node.signature_scheme)

        # One identity across every commit is the whole point: a signature
        # under a key that changes per node attributes nothing.
        assert len(keys) == 1
        assert schemes == {"pqc-ml-dsa"}
        assert identity.exists()

    def test_the_identity_file_is_private(self, tmp_path: Path) -> None:
        pytest.importorskip("aegis_rust")
        identity = tmp_path / "ledger.pqc"
        with CryptographicAuditLedger(
            str(tmp_path / "b.wal"),
            signing_key=SIGNING_KEY,
            pqc_identity_path=str(identity),
        ) as ledger:
            ledger.commit_state(state_id="req", entropy=0.5, payload=b"x")
        # It holds the raw ML-DSA private key.
        assert identity.stat().st_mode & 0o777 == 0o600

    def test_the_identity_survives_a_restart(self, tmp_path: Path) -> None:
        pytest.importorskip("aegis_rust")
        identity = tmp_path / "ledger.pqc"
        with CryptographicAuditLedger(
            str(tmp_path / "c.wal"),
            signing_key=SIGNING_KEY,
            pqc_identity_path=str(identity),
        ) as first:
            before = first.commit_state(state_id="a", entropy=0.5, payload=b"x").public_key
        with CryptographicAuditLedger(
            str(tmp_path / "d.wal"),
            signing_key=SIGNING_KEY,
            pqc_identity_path=str(identity),
        ) as second:
            after = second.commit_state(state_id="b", entropy=0.5, payload=b"x").public_key

        assert before == after

    def test_without_an_identity_it_falls_through_to_hmac(self, tmp_path: Path) -> None:
        # The tier is skipped rather than satisfied with a one-shot key. HMAC
        # is a weaker claim than ML-DSA but a true one; a discarded-key
        # signature labelled ``pqc-ml-dsa`` is a stronger claim than the
        # evidence supports.
        with CryptographicAuditLedger(str(tmp_path / "e.wal"), signing_key=SIGNING_KEY) as ledger:
            node = ledger.commit_state(state_id="req", entropy=0.5, payload=b"x")
        assert node.signature_scheme == "hmac-sha256"


class TestTheIdentityIsNotTrustedBlindly:
    """Two ways a persistent identity stops attributing anything.

    Both were raised in review on the change that introduced it, and both are
    the same failure the persistent identity exists to prevent: a node labelled
    ``pqc-ml-dsa`` whose public key nobody holds.
    """

    @pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o666])
    def test_a_group_or_world_readable_identity_is_refused(self, tmp_path: Path, mode: int) -> None:
        # A key every account on the host can read attributes to all of them.
        # Refusing is loud and leaves signing on HMAC; silently tightening the
        # mode would not un-expose a key that has already been readable.
        pytest.importorskip("aegis_rust")
        identity = tmp_path / "loose.pqc"
        with CryptographicAuditLedger(
            str(tmp_path / "f.wal"), signing_key=SIGNING_KEY, pqc_identity_path=str(identity)
        ) as ledger:
            ledger.commit_state(state_id="seed", entropy=0.5, payload=b"x")

        identity.chmod(mode)
        with CryptographicAuditLedger(
            str(tmp_path / "g.wal"), signing_key=SIGNING_KEY, pqc_identity_path=str(identity)
        ) as ledger:
            node = ledger.commit_state(state_id="req", entropy=0.5, payload=b"x")

        assert node.signature_scheme == "hmac-sha256"
        assert node.public_key == ""
        # Refused, not repaired: the mode is the operator's to explain.
        assert identity.stat().st_mode & 0o777 == mode

    def test_a_private_identity_is_still_accepted(self, tmp_path: Path) -> None:
        # The guard rejects a permissive mode, not every mode but 0600 — an
        # identity provisioned read-only must still load.
        pytest.importorskip("aegis_rust")
        identity = tmp_path / "tight.pqc"
        with CryptographicAuditLedger(
            str(tmp_path / "h.wal"), signing_key=SIGNING_KEY, pqc_identity_path=str(identity)
        ) as ledger:
            before = ledger.commit_state(state_id="seed", entropy=0.5, payload=b"x").public_key

        identity.chmod(0o400)
        with CryptographicAuditLedger(
            str(tmp_path / "i.wal"), signing_key=SIGNING_KEY, pqc_identity_path=str(identity)
        ) as ledger:
            node = ledger.commit_state(state_id="req", entropy=0.5, payload=b"x")

        assert node.signature_scheme == "pqc-ml-dsa"
        assert node.public_key == before

    def test_a_directory_at_the_identity_path_is_refused(self, tmp_path: Path) -> None:
        pytest.importorskip("aegis_rust")
        identity = tmp_path / "not-a-file"
        identity.mkdir()
        with CryptographicAuditLedger(
            str(tmp_path / "j.wal"), signing_key=SIGNING_KEY, pqc_identity_path=str(identity)
        ) as ledger:
            node = ledger.commit_state(state_id="req", entropy=0.5, payload=b"x")

        assert node.signature_scheme == "hmac-sha256"

    def test_a_writer_that_loses_the_publish_race_adopts_the_winner(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The create race, driven deterministically.

        Two processes pointed at one absent identity path both find it missing
        and both generate a keypair — ML-DSA keygen holds that window open for
        milliseconds. The one that publishes second must sign under what is on
        disk, not under what it generated, or its nodes carry a `pqc-ml-dsa`
        public key that exists nowhere and attributes to nobody.

        The window is entered deterministically rather than raced: a competitor's
        identity is planted at the path *during* this ledger's keygen, which is
        exactly the state a loser finds on return from generating. Publishing by
        replace would overwrite the competitor and keep the locally generated
        key — orphaning the competitor's already-signed nodes. Publishing by
        create-if-absent cannot, so the local keypair is discarded instead.
        """
        pytest.importorskip("aegis_rust")
        from aegis.core import crypto_audit as _module

        identity = tmp_path / "contested.pqc"
        competitor = _module.PQCSigner(require_real=True)
        material = competitor.public_key + competitor.export_private_key()

        class PublishesACompetitorMidKeygen(_module.PQCSigner):  # type: ignore[misc,valid-type]
            def __init__(self, *args: object, **kwargs: object) -> None:
                super().__init__(*args, **kwargs)  # type: ignore[arg-type]
                if not identity.exists():
                    identity.write_bytes(material)
                    identity.chmod(0o600)

        monkeypatch.setattr(_module, "PQCSigner", PublishesACompetitorMidKeygen)

        with CryptographicAuditLedger(
            str(tmp_path / "k.wal"), signing_key=SIGNING_KEY, pqc_identity_path=str(identity)
        ) as ledger:
            node = ledger.commit_state(state_id="a", entropy=0.5, payload=b"x")

        assert node.signature_scheme == "pqc-ml-dsa"
        # Signed under the published identity, not the one generated here.
        assert node.public_key == competitor.public_key.hex()
        # And the competitor's file was adopted, never overwritten.
        assert identity.read_bytes() == material

    def test_publishing_leaves_no_temporary_files_behind(self, tmp_path: Path) -> None:
        pytest.importorskip("aegis_rust")
        identity = tmp_path / "clean.pqc"
        with CryptographicAuditLedger(
            str(tmp_path / "m.wal"), signing_key=SIGNING_KEY, pqc_identity_path=str(identity)
        ) as ledger:
            ledger.commit_state(state_id="req", entropy=0.5, payload=b"x")

        assert list(tmp_path.glob("*.tmp")) == []


class TestNewChainsUseDomainSeparation:
    """P1-2: a new chain defaulted to the construction v2 exists to replace."""

    def test_a_new_chain_uses_v2(self, tmp_path: Path) -> None:
        with CryptographicAuditLedger(str(tmp_path / "new.wal"), signing_key=SIGNING_KEY) as ledger:
            assert ledger.mmr_hash_scheme == MMR_NEW_CHAIN_DEFAULT_SCHEME
            assert ledger.mmr_hash_scheme == HASH_SCHEME_V2

    def test_an_existing_v1_chain_still_opens_under_v1(self, tmp_path: Path) -> None:
        # The reason the default is 'auto' rather than v2 outright: a plain v2
        # default would refuse every chain already in the field, turning an
        # upgrade into an outage.
        wal = tmp_path / "legacy.wal"
        with CryptographicAuditLedger(
            str(wal), signing_key=SIGNING_KEY, mmr_hash_scheme=HASH_SCHEME_V1
        ) as first:
            for index in range(4):
                first.commit_state(state_id=f"r{index}", entropy=0.5, payload=b"x")
            root_before = first.chain[-1].merkle_root

        with CryptographicAuditLedger(
            str(wal), signing_key=SIGNING_KEY, mmr_hash_scheme=MMR_SCHEME_AUTO
        ) as reopened:
            assert reopened.mmr_hash_scheme == HASH_SCHEME_V1
            assert reopened._fault_state == "healthy"
            assert reopened.chain[-1].merkle_root == root_before
            valid, index = reopened.verify_integrity()
            assert valid is True
            assert index is None

    def test_an_existing_v2_chain_reopens_under_v2(self, tmp_path: Path) -> None:
        wal = tmp_path / "modern.wal"
        with CryptographicAuditLedger(str(wal), signing_key=SIGNING_KEY) as first:
            for index in range(4):
                first.commit_state(state_id=f"r{index}", entropy=0.5, payload=b"x")
            root_before = first.chain[-1].merkle_root

        with CryptographicAuditLedger(str(wal), signing_key=SIGNING_KEY) as reopened:
            assert reopened.mmr_hash_scheme == HASH_SCHEME_V2
            assert reopened._fault_state == "healthy"
            assert reopened.chain[-1].merkle_root == root_before

    @pytest.mark.parametrize(
        ("written", "pinned"),
        [(HASH_SCHEME_V1, HASH_SCHEME_V2), (HASH_SCHEME_V2, HASH_SCHEME_V1)],
    )
    def test_an_explicit_pin_against_the_wrong_chain_still_fails_closed(
        self, tmp_path: Path, written: str, pinned: str
    ) -> None:
        # Adoption applies only to 'auto'. An operator who names a scheme means
        # it, and a chain written under the other one is refused by name rather
        # than replayed to a different root.
        wal = tmp_path / "pinned.wal"
        with CryptographicAuditLedger(
            str(wal), signing_key=SIGNING_KEY, mmr_hash_scheme=written
        ) as first:
            first.commit_state(state_id="r0", entropy=0.5, payload=b"x")

        with CryptographicAuditLedger(
            str(wal), signing_key=SIGNING_KEY, mmr_hash_scheme=pinned
        ) as second:
            assert second._fault_state == "mmr_scheme_mismatch"
