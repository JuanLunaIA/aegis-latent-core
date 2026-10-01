# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
from __future__ import annotations

import hmac

from aegis.auth.apikey import constant_time_key_in


def test_constant_time_key_in_matches_valid_key() -> None:
    keys = frozenset({"alpha-key", "beta-key"})
    assert constant_time_key_in("alpha-key", keys) is True
    assert constant_time_key_in("gamma-key", keys) is False


def test_constant_time_key_in_rejects_near_miss_without_short_circuit() -> None:
    keys = frozenset({"super-secret-key-value"})
    almost = "super-secret-key-valuf"
    assert constant_time_key_in(almost, keys) is False
    assert hmac.compare_digest("super-secret-key-value", "super-secret-key-value")


def test_constant_time_key_in_empty_keyset() -> None:
    assert constant_time_key_in("any-key", frozenset()) is False
