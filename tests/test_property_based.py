"""
tests/test_property_based.py — Property-based testing for Aegis Core.
"""
from __future__ import annotations
import unittest
import os
import tempfile
import hypothesis.strategies as st
from hypothesis import given
from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.timing_defense import TimingDefense
from aegis.core.memory import Zeroize


@given(
    state_id=st.text(min_size=1, max_size=100).filter(lambda x: "\x00" not in x),
    entropy=st.floats(allow_nan=False, allow_infinity=False),
    payload=st.binary(min_size=0, max_size=1024),
    tenant_id=st.text(min_size=1, max_size=50)
)
def test_ledger_integrity_property(state_id, entropy, payload, tenant_id):
    """
    Property: Every commit must result in a valid chain state and a verifiable root.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger_path = os.path.join(tmpdir, "prop_test.wal")
        ledger = CryptographicAuditLedger(
            persistence_path=ledger_path,
            max_memory_nodes=100
        )
        node = ledger.commit_state(state_id, entropy, payload, tenant_id)
        is_valid, err = ledger.verify_integrity()
        assert is_valid, f"Integrity check failed: {err}"
        assert node.merkle_root == ledger.chain[-1].merkle_root
        ledger.close()


@given(
    val1=st.binary(min_size=1, max_size=1024),
    val2=st.binary(min_size=1, max_size=1024)
)
def test_timing_defense_property(val1, val2):
    """
    Property: constant_time_compare must behave identically to == 
    but without early-exit optimization.
    """
    result = TimingDefense.constant_time_compare(val1, val2)
    assert result == (val1 == val2)


@given(data=st.binary(min_size=1, max_size=1024))
def test_zeroization_property(data):
    """
    Property: After Zeroize.wipe(), the buffer must contain only zeros.
    """
    buf = bytearray(data)
    Zeroize.wipe(buf)
    assert all(b == 0 for b in buf)
