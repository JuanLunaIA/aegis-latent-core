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
    commitment = SHA-256(0x00 || ciphertext)       # this is what the MMR commits
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

_NONCE_BYTES: Final[int] = 12  # 96-bit, the GCM-recommended size

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
    "SealedPayload",
    "ShredderError",
    "ShredderIntegrityError",
    "ShredderKeyDestroyedError",
]
