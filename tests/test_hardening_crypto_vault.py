# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
"""Failed key-vault commits must not leak uncommitted state to later calls."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from aegis.core.crypto_shredder import CryptoShredder


@pytest.mark.parametrize("operation", ["seal", "erase"])
def test_failed_vault_commit_rolls_back_before_reuse(tmp_path: Path, operation: str) -> None:
    vault = CryptoShredder(tmp_path / "vault")
    db = vault._db
    if operation == "erase":
        vault.seal("subject", b"synthetic")

    class FailedCommit:
        def commit(self):
            raise sqlite3.OperationalError("injected commit failure")

        def __getattr__(self, name):
            return getattr(db, name)

    vault._db = FailedCommit()
    try:
        with pytest.raises(sqlite3.OperationalError):
            if operation == "seal":
                vault.seal("subject", b"synthetic")
            else:
                vault.erase("subject")
        assert not db.in_transaction
        assert vault.has_key("subject") is (operation == "erase")
    finally:
        vault._db = db
        vault.close()
