"""
tests/test_shredded_digest_confirmability.py — an erased record stops answering.

Cryptographic shredding destroys the subject key, so the sealed leaf becomes
unreadable. Until REG-012 the node still carried ``request_hash`` and
``response_hash`` as a plain ``SHA-256`` of the payload, and those survive the
key. An adversary holding the ciphertext and a *guess* could hash the guess and
compare: the record answered "was it this?" long after it was supposed to have
been erased.

That is not a theoretical weakness. AI requests are frequently low-entropy —
a support template, a form, a name in a fixed sentence — so the guess space is
often small enough to enumerate. The envelope encryption was AES-256-GCM and
the confirmation oracle sat next to it in cleartext.

The fix keys those digests to the subject, with the salt derived from the
subject key rather than stored beside it, so the one row ``shred`` deletes takes
both. What these tests pin:

* the digest is not a plain ``SHA-256``, so a guess cannot be confirmed by
  hashing it;
* the same bytes under two subjects produce different digests, so a digest
  cannot be used to correlate one subject's content against another's;
* shredding destroys the ability to recompute, which is the property that makes
  erasure mean something;
* **signature verification survives the shred** — the chain still verifies with
  the key gone, because verification reads stored fields and never re-hashes
  plaintext. If this broke, the fix would have traded a confidentiality gain for
  an integrity loss, and that trade is not acceptable;
* with shredding off, nothing changes at all.

The cost is stated in the code and repeated here because it is inherent rather
than incidental: a third party holding the original request can no longer
confirm it against the node by hashing either. For a subject whose content is
meant to be unrecoverable, "confirmable by an auditor" and "unconfirmable by an
adversary" are the same property, so no scheme delivers both.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.crypto_shredder import SHRED_SCHEME_UNSEALED, SHRED_SCHEME_V2

_SUBJECT = "tenant-alpha"
_OTHER = "tenant-beta"

# Deliberately guessable. This is what the attack needs and what real traffic
# frequently looks like.
_GUESSABLE = b'{"messages":[{"role":"user","content":"What is my account balance?"}]}'


def _ledger(tmp_path: Path, *, shredding: bool, **kw: Any) -> CryptographicAuditLedger:
    return CryptographicAuditLedger(
        str(tmp_path / "w.jsonl"),
        signing_key="reg-012-test-key",
        enable_cryptographic_shredding=shredding,
        **kw,
    )


def test_the_stored_digest_is_not_a_plain_hash_of_the_payload(tmp_path: Path) -> None:
    """The confirmation oracle is what REG-012 removes."""
    ledger = _ledger(tmp_path, shredding=True)
    node = ledger.commit_forensic(state_id="req-1", request_bytes=_GUESSABLE, tenant_id=_SUBJECT)
    ledger.close()

    assert node.request_hash != hashlib.sha256(_GUESSABLE).hexdigest()
    assert len(node.request_hash) == 64


def test_the_same_payload_under_two_subjects_digests_differently(tmp_path: Path) -> None:
    """A shared digest would correlate subjects across an erasure boundary."""
    ledger = _ledger(tmp_path, shredding=True)
    a = ledger.commit_forensic(state_id="a", request_bytes=_GUESSABLE, tenant_id=_SUBJECT)
    b = ledger.commit_forensic(state_id="b", request_bytes=_GUESSABLE, tenant_id=_OTHER)
    ledger.close()

    assert a.request_hash != b.request_hash


def test_shredding_destroys_the_ability_to_recompute_the_digest(tmp_path: Path) -> None:
    """After the key is gone the digest cannot be reproduced from the plaintext.

    This is the whole point: the record stops answering "was it this?".
    """
    ledger = _ledger(tmp_path, shredding=True)
    node = ledger.commit_forensic(state_id="req-1", request_bytes=_GUESSABLE, tenant_id=_SUBJECT)
    shredder = ledger._shredder
    assert shredder is not None
    before = shredder.digest(_SUBJECT, _GUESSABLE)
    assert before == node.request_hash, "precondition: the digest is reproducible while keyed"

    assert ledger.crypto_shred(_SUBJECT) is True

    after = shredder.digest(_SUBJECT, _GUESSABLE)
    ledger.close()
    assert after != before, "a destroyed key must not reproduce the original digest"


def test_the_chain_still_verifies_after_the_key_is_destroyed(tmp_path: Path) -> None:
    """Confidentiality gain must not cost integrity.

    ``verify_integrity`` recomputes over the node's stored fields, so a digest
    it can no longer *derive* is still a digest it can still *check*. If this
    regressed, the fix would be trading one property for another rather than
    adding one.
    """
    ledger = _ledger(tmp_path, shredding=True)
    for index in range(3):
        ledger.commit_forensic(
            state_id=f"req-{index}", request_bytes=_GUESSABLE, tenant_id=_SUBJECT
        )
    assert ledger.verify_integrity() == (True, None)

    ledger.crypto_shred(_SUBJECT)
    outcome = ledger.verify_integrity()
    ledger.close()
    assert outcome == (True, None), "the chain must verify with the key gone"


def test_the_node_records_the_scheme_that_produced_its_digests(tmp_path: Path) -> None:
    """A reader must not assume a v2 node carries v1's confirmable digests."""
    ledger = _ledger(tmp_path, shredding=True)
    node = ledger.commit_forensic(state_id="req-1", request_bytes=_GUESSABLE, tenant_id=_SUBJECT)
    ledger.close()
    assert node.shredding_version == SHRED_SCHEME_V2


def test_with_shredding_off_the_digest_is_unchanged(tmp_path: Path) -> None:
    """The default path must be byte-identical to what it always was.

    Every chain written without shredding keeps a plain `SHA-256`, so an
    existing deployment sees no change and an auditor keeps the confirmation
    capability that only costs something once erasure is in play.
    """
    ledger = _ledger(tmp_path, shredding=False)
    node = ledger.commit_forensic(state_id="req-1", request_bytes=_GUESSABLE, tenant_id=_SUBJECT)
    ledger.close()

    assert node.request_hash == hashlib.sha256(_GUESSABLE).hexdigest()
    assert node.shredding_version == SHRED_SCHEME_UNSEALED


def test_a_rejection_digest_is_keyed_too(tmp_path: Path) -> None:
    """Refusals carry payload digests as well, and shredding must cover them.

    A refused request is committed to the same chain (`CLM-060`). Leaving its
    digest plain would erase the admitted traffic and leave the blocked traffic
    confirmable, which is the wrong way round — a refusal often records exactly
    the content someone later wants erased.
    """
    ledger = _ledger(tmp_path, shredding=True)
    node = ledger.commit_rejection(
        state_id="rej-1",
        request_bytes=_GUESSABLE,
        rejection_code=403,
        reason_category="waf_block_layer1",
        tenant_id=_SUBJECT,
    )
    ledger.close()
    assert node.request_hash != hashlib.sha256(_GUESSABLE).hexdigest()
