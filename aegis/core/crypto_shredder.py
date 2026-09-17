# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Cryptographic erasure for an append-only ledger.

An append-only Merkle ledger and a right-to-erasure request pull in opposite
directions: deleting a record rewrites every downstream hash and invalidates
the root. Cryptographic erasure sidesteps that. The ledger commits to a
*ciphertext*, never the plaintext, and erasure destroys the key instead of the
record. The ciphertext, the WAL line, every peak and the root stay exactly as
they were, so previously issued inclusion proofs keep verifying.

    seal(subject, plaintext) -> SealedPayload      # key minted, kept in a vault
    commitment = SHA-256(0x00 || nonce || ciphertext)   # what the MMR commits
    erase(subject)                                 # key destroyed; ciphertext kept
    open(sealed) -> ShredderKeyDestroyedError      # plaintext unrecoverable

Primitives
----------

AES-256-GCM from ``cryptography``. Nothing here is hand-rolled: no bespoke
commitment scheme, no curve arithmetic, no custom KDF. A 96-bit nonce is drawn
per seal from ``os.urandom``, which matters because GCM nonce reuse under one
key is catastrophic — the vault therefore mints one key per subject and the
nonce is never derived from data.

What erasure does and does not establish
----------------------------------------

Destroying the key makes the plaintext unrecoverable *to anyone who has only
the ciphertext*, at the strength of AES-256-GCM. That is the claim, and it is
the only one.

It is **not** a guarantee that the key is gone from the physical medium. This
runs in CPython on a general-purpose OS, and none of the following are under
its control: pages the allocator already copied, the SQLite rollback journal or
WAL, filesystem journaling, page cache, swap, snapshots, backups, replicas, or
an SSD's wear-levelling and over-provisioned blocks, where an overwrite does
not touch the cell that held the old value. ``bytearray`` zeroization below is
best-effort hygiene against a casual memory scrape, not a media-sanitisation
guarantee, and ``str`` keys cannot be zeroized at all because CPython interns
and copies them freely.

Operationally that means the vault must live on media the operator can
sanitise, or the key material must be held somewhere with its own destruction
guarantee (an HSM or a KMS with key deletion). Deployment acceptance is
required before anyone calls this compliant with a specific regulation. This
module implements a mechanism; it makes no legal claim, and no statement here
is legal advice.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
import threading
from dataclasses import dataclass
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#: Domain tag on the commitment, matching the ``aegis-mmr-inclusion-v2`` leaf
#: tag so a commitment cannot be confused with an interior node.
_DOMAIN_COMMITMENT: Final[bytes] = b"\x00"

# ── Sealing scheme identifiers ────────────────────────────────────────────────
#
# The name records which construction produced a record's commitment, and it
# exists for the reason the MMR's `HASH_SCHEME_V1`/`HASH_SCHEME_V2` pair does:
# an unlabelled hash construction is a migration trap. A verifier recomputing
# `SHA-256(0x00 || nonce || ciphertext)` against a record sealed under some
# later scheme would not get a mismatch it could attribute — it would get a
# mismatch indistinguishable from tampering.
#
# This is forward-compatibility, not a present ambiguity: a record already
# discloses *that* it is sealed by carrying `sealed_ciphertext`. What it could
# not say until now is *how*.
#
# Deliberately no validator alongside these, unlike `aegis.core.forensic`'s
# `validate_waf_verdict`. That function guards a real boundary: `waf_verdict`
# is a public `commit_forensic` keyword argument, so a caller can hand it
# anything. `shredding_version` has no such entry point — every write site
# derives it from `SealedPayload.scheme` or the constant below, never from
# caller input — so a validator here would guard a boundary that does not
# exist. `status`, `mmr_leaf_hash` and the other unbound fields on `AuditNode`
# are unvalidated for the identical reason. Add one if a second scheme ever
# makes `scheme` a real choice rather than a hardcoded return.
SHRED_SCHEME_V1: Final[str] = "v1-aesgcm256-sha256"
#: Adds keyed request/response digests to `v1`. Under `v1` the node retained a
#: plain `SHA-256` of the payload, so a guessed plaintext could be confirmed
#: against an erased record -- the ciphertext was unreadable and the digest
#: still answered "was it this?". Under `v2` those digests are HMAC-SHA256 under
#: a salt derived from the subject key, so destroying the key destroys the
#: ability to pose that question.
#:
#: The cost is real and inherent, not a design slip: a third party holding the
#: original request can no longer confirm it against the node by hashing. For a
#: subject whose content is meant to be unrecoverable those two properties are
#: contradictory, so no scheme provides both.
SHRED_SCHEME_V2: Final[str] = "v2-aesgcm256-hmacsha256"
#: No envelope: the record's `mmr_leaf_hash` is a digest of the leaf bytes
#: themselves. This is what every node written with shredding off carries, and
#: what every node written before this field existed carries. It is the absence
#: of sealing, not a sealing scheme.
SHRED_SCHEME_UNSEALED: Final[str] = ""


_NONCE_BYTES: Final[int] = 12  # 96-bit, the GCM-recommended size

#: Domain separator for the digest salt. Distinct from any encryption use of
#: the same key, so the salt can never collide with key material used elsewhere.
_DIGEST_SALT_INFO: Final[bytes] = b"aegis-shred-digest-salt-v1"

_SCHEMA: Final[str] = """
CREATE TABLE IF NOT EXISTS subject_keys (
    subject_id TEXT PRIMARY KEY,
    key        BLOB NOT NULL
) WITHOUT ROWID;
"""


class ShredderError(RuntimeError):
    """Base class for shredder failures."""


class ShredderKeyDestroyedError(ShredderError):
    """The subject's key was erased, so the plaintext is unrecoverable.

    Distinct from a decryption failure on purpose: an operator reading a log
    needs to tell "this was erased under a retention policy" apart from "this
    ciphertext is corrupt", and the two demand different responses.
    """


class ShredderIntegrityError(ShredderError):
    """The ciphertext failed authentication under a key that is still present."""


@dataclass(frozen=True, slots=True)
class SealedPayload:
    """A sealed record. Safe to persist; contains no key material."""

    subject_id: str
    nonce: bytes
    ciphertext: bytes

    @property
    def commitment(self) -> bytes:
        """The value the ledger commits to.

        Covers the nonce as well as the ciphertext: committing to the
        ciphertext alone would leave the nonce free to be swapped, and GCM
        authenticates the ciphertext under a *given* nonce.
        """

        return hashlib.sha256(_DOMAIN_COMMITMENT + self.nonce + self.ciphertext).digest()

    @property
    def commitment_hex(self) -> str:
        return self.commitment.hex()

    @property
    def scheme(self) -> str:
        """The construction that produced :attr:`commitment`.

        Read from the payload rather than assumed by the caller, so a record
        and the scheme recorded beside it cannot drift apart at the one place
        they are written together.

        ``v2`` since REG-012. The envelope construction is byte-identical to
        ``v1`` -- what changed is that a ledger holding this payload also keys
        its request and response digests to the same destructible subject key,
        so the scheme identifier moves to keep a reader from assuming a ``v2``
        node carries ``v1``'s confirmable plain digests.
        """

        return SHRED_SCHEME_V2


class CryptoShredder:
    """Per-subject envelope encryption with destructible keys.

    The vault is mutable by design — it is the only part of the system that is.
    The ledger stays append-only; erasure happens here.
    """

    def __init__(self, vault_path: str | os.PathLike[str] | None = None) -> None:
        """Open or create the key vault.

        ``None`` keeps keys in memory only, which is the right default for a
        test and the wrong one for a deployment: an in-memory vault loses every
        key on restart, which decrypts nothing rather than leaking anything.
        """

        self._lock = threading.Lock()
        self._path = os.fspath(vault_path) if vault_path is not None else ":memory:"
        self._db = sqlite3.connect(self._path, check_same_thread=False)
        if self._path != ":memory:":
            # Owner-only: the vault is the whole security boundary.
            os.chmod(self._path, 0o600)
        self._db.execute(_SCHEMA)
        self._db.commit()

    # ── key handling ────────────────────────────────────────────────────

    def _fetch_key(self, subject_id: str) -> bytes | None:
        row = self._db.execute(
            "SELECT key FROM subject_keys WHERE subject_id = ?", (subject_id,)
        ).fetchone()
        return None if row is None else bytes(row[0])

    def _key_for_seal(self, subject_id: str) -> bytes:
        existing = self._fetch_key(subject_id)
        if existing is not None:
            return existing
        key = AESGCM.generate_key(bit_length=256)
        self._db.execute(
            "INSERT INTO subject_keys (subject_id, key) VALUES (?, ?)",
            (subject_id, key),
        )
        self._db.commit()
        return key

    # ── public surface ──────────────────────────────────────────────────

    def seal(self, subject_id: str, plaintext: bytes) -> SealedPayload:
        """Encrypt ``plaintext`` under ``subject_id``'s key."""

        if not subject_id:
            raise ValueError("subject_id must not be empty")
        with self._lock:
            key = self._key_for_seal(subject_id)
            nonce = os.urandom(_NONCE_BYTES)
            # The subject is bound as associated data, so a ciphertext cannot
            # be replayed under a different subject even by someone holding
            # both keys.
            ciphertext = AESGCM(key).encrypt(nonce, plaintext, subject_id.encode("utf-8"))
        return SealedPayload(subject_id, nonce, ciphertext)

    def digest(self, subject_id: str, data: bytes) -> str:
        """Return a keyed digest of ``data`` that dies with ``subject_id``'s key.

        Mechanism: the salt is ``HMAC(subject_key, "aegis-shred-digest-salt-v1")``
        and the digest is ``HMAC(salt, data)``. The salt is *derived*, never
        stored, so ``shred`` removing the one key row removes the salt with it.
        A second stored secret would be a second thing to forget to delete.

        What this buys: after the key is destroyed the stored digest is an
        opaque 64-hex value. Without the salt an adversary holding a candidate
        plaintext cannot confirm it against the record, which is what a plain
        ``SHA-256`` of the payload would have let them do however strong the
        envelope encryption was.

        What it costs: a verifier who holds the original request can no longer
        confirm it against the node by hashing either. That is the same
        capability, and for an erased subject it cannot be kept while also
        making the content unconfirmable -- the two are contradictory. Signature
        verification is unaffected: ``verify_integrity`` recomputes over the
        node's *stored* fields and never re-hashes plaintext.

        Creates the subject's key when absent, exactly as ``seal`` does, so a
        digest and the seal beside it always share one destructible key.
        """

        if not subject_id:
            raise ValueError("subject_id must not be empty")
        with self._lock:
            key = self._key_for_seal(subject_id)
        salt = hmac.new(key, _DIGEST_SALT_INFO, hashlib.sha256).digest()
        return hmac.new(salt, data, hashlib.sha256).hexdigest()

    def open(self, sealed: SealedPayload) -> bytes:
        """Decrypt, or say precisely why it cannot be decrypted."""

        with self._lock:
            key = self._fetch_key(sealed.subject_id)
            if key is None:
                raise ShredderKeyDestroyedError(
                    f"no key for subject {sealed.subject_id!r}: it was erased or "
                    f"never sealed, so the plaintext is unrecoverable"
                )
            try:
                return AESGCM(key).decrypt(
                    sealed.nonce,
                    sealed.ciphertext,
                    sealed.subject_id.encode("utf-8"),
                )
            except InvalidTag as exc:
                raise ShredderIntegrityError(
                    f"ciphertext for subject {sealed.subject_id!r} failed "
                    f"authentication under a key that is still present"
                ) from exc

    def erase(self, subject_id: str) -> bool:
        """Destroy a subject's key. Returns whether one was present.

        Idempotent: erasing an already-erased subject is not an error, because
        a retention job re-running must not fail.

        Read the module docstring on what this does not guarantee about the
        physical medium.
        """

        with self._lock:
            key = self._fetch_key(subject_id)
            if key is None:
                return False

            # Best-effort scrub of the copy this process is holding. CPython
            # gives no way to reach the other copies, and the comment exists so
            # nobody mistakes this for media sanitisation.
            scratch = bytearray(key)
            for i in range(len(scratch)):
                scratch[i] = 0
            del scratch

            self._db.execute("DELETE FROM subject_keys WHERE subject_id = ?", (subject_id,))
            self._db.commit()
            # Rewrites the database file, dropping the freed page that held the
            # key rather than leaving it allocated. This is a smaller claim
            # than sanitisation: see the module docstring.
            self._db.execute("VACUUM")
            self._db.commit()
            return True

    def has_key(self, subject_id: str) -> bool:
        with self._lock:
            return self._fetch_key(subject_id) is not None

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def __enter__(self) -> CryptoShredder:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


__all__ = [
    "CryptoShredder",
    "SHRED_SCHEME_UNSEALED",
    "SHRED_SCHEME_V1",
    "SealedPayload",
    "ShredderError",
    "ShredderIntegrityError",
    "ShredderKeyDestroyedError",
]
