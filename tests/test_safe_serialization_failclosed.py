# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""The guarded-pickle helpers fail closed, and keep failing closed.

``aegis/core/safe_serialization.py`` is a compromise the module docstring states
plainly: pickle stays reachable, so the mitigation is an allow-list plus an HMAC
signature. Every uncovered branch in it was a *decision* rather than a line —
what happens with no key configured, with a signature that does not match, with
a signature file that cannot be read, with an object that is not allowed to be
written. Getting any of those wrong is silent: an artifact written without the
signature its reader is about to require, or a load that proceeds because the
key was missing rather than failing.

So the assertions here are about refusals, not round-trips:

* no key → ``SerializationError`` / ``SignatureVerificationError``, never a
  default or empty key and never an unsigned artifact that reports success;
* a mismatch, a missing signature file, or an unreadable one → refused, with the
  reason distinguished so an operator can act on it;
* a payload that only becomes disallowed *after* unpickling → refused, because
  ``find_class`` cannot see an ``int`` built from a primitive opcode;
* an object outside the allow-list → refused *before* anything is written.

The load path is exercised by writing real pickle bytes, and the tests probe the
exception that actually comes out rather than the one that seems likely: a
truncated stream raises ``UnpicklingError`` here, which is reported as
``UnsafePickleError``, not the generic wrapper.
"""

from __future__ import annotations

import hashlib
import hmac
import pickle
from pathlib import Path

import pytest

from aegis.core import safe_serialization
from aegis.core.safe_serialization import (
    DEFAULT_ALLOWED,
    SerializationError,
    SignatureVerificationError,
    UnsafePickleError,
    _validate_allowed,
    safe_pickle_dump,
    safe_pickle_load,
    sign_artifact,
    verify_artifact_signature,
)

KEY = b"k" * 32


@pytest.fixture
def no_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """The module-level key is read at import, so a configured environment does
    not leak into the "no key" cases."""
    monkeypatch.setattr(safe_serialization, "_PICKLE_HMAC_KEY", b"")


@pytest.fixture
def with_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(safe_serialization, "_PICKLE_HMAC_KEY", KEY)


class TestSigningWithoutAKey:
    def test_sign_refuses_rather_than_using_an_empty_key(self, no_key: None) -> None:
        with pytest.raises(SerializationError, match="HMAC key not configured"):
            sign_artifact(b"payload")

    def test_verify_refuses_rather_than_accepting_anything(self, no_key: None) -> None:
        with pytest.raises(SignatureVerificationError, match="HMAC key not configured"):
            verify_artifact_signature(b"payload", b"signature")

    def test_an_explicit_key_is_used_verbatim(self) -> None:
        """The signature must be HMAC-SHA256 of the exact bytes, recomputed here."""
        data = b"the artifact"
        returned, signature = sign_artifact(data, key=KEY)
        assert returned == data
        assert signature == hmac.new(KEY, data, hashlib.sha256).digest()
        assert verify_artifact_signature(data, signature, key=KEY) is True

    def test_a_one_bit_change_is_rejected(self) -> None:
        data = b"the artifact"
        _, signature = sign_artifact(data, key=KEY)
        flipped = bytes([signature[0] ^ 0x01]) + signature[1:]
        with pytest.raises(SignatureVerificationError, match="verification failed"):
            verify_artifact_signature(data, flipped, key=KEY)


class TestLoadRequiresAValidSignature:
    def test_a_missing_signature_file_is_refused(self, tmp_path: Path, with_key: None) -> None:
        path = tmp_path / "artifact.pkl"
        path.write_bytes(pickle.dumps({"a": 1}))
        with pytest.raises(SignatureVerificationError, match="Signature file not found"):
            safe_pickle_load(path, require_signature=True)

    def test_the_default_signature_path_is_the_suffix_plus_sig(
        self, tmp_path: Path, with_key: None
    ) -> None:
        path = tmp_path / "artifact.pkl"
        path.write_bytes(pickle.dumps({"a": 1}))
        _, signature = sign_artifact(path.read_bytes())
        signature_path = tmp_path / "artifact.pkl.sig"
        assert signature_path == path.with_suffix(path.suffix + ".sig")
        signature_path.write_bytes(signature)
        assert safe_pickle_load(path, require_signature=True) == {"a": 1}

    def test_a_tampered_payload_is_refused_even_with_a_signature_file(
        self, tmp_path: Path, with_key: None
    ) -> None:
        """A valid signature over different bytes is exactly the attack this guards."""
        path = tmp_path / "artifact.pkl"
        path.write_bytes(pickle.dumps({"balance": 10}))
        _, signature = sign_artifact(path.read_bytes())
        path.with_suffix(".pkl.sig").write_bytes(signature)
        path.write_bytes(pickle.dumps({"balance": 999}))
        with pytest.raises(SignatureVerificationError):
            safe_pickle_load(path, require_signature=True)

    def test_an_unreadable_signature_file_is_wrapped_with_the_os_reason(
        self, tmp_path: Path, with_key: None
    ) -> None:
        path = tmp_path / "artifact.pkl"
        path.write_bytes(pickle.dumps({"a": 1}))
        path.with_suffix(".pkl.sig").mkdir()
        with pytest.raises(SignatureVerificationError, match="Failed to read signature files"):
            safe_pickle_load(path, require_signature=True)


class TestLoadRefusesPayloadsItCannotVouchFor:
    def test_a_truncated_stream_is_reported_as_unsafe_not_unpickled(
        self, tmp_path: Path, with_key: None
    ) -> None:
        path = tmp_path / "truncated.pkl"
        path.write_bytes(b"\x80\x05\x95\x00\x00")
        with pytest.raises(UnsafePickleError, match="Unpickling failed"):
            safe_pickle_load(path, require_signature=False)

    def test_a_type_that_only_appears_after_unpickling_is_refused(
        self, tmp_path: Path, with_key: None
    ) -> None:
        """``int`` arrives through a primitive opcode, so no ``find_class`` call
        stands between it and the object graph; the post-load check is the only
        thing that sees it."""
        path = tmp_path / "int.pkl"
        path.write_bytes(pickle.dumps(42))
        with pytest.raises(UnsafePickleError, match="disallowed types after load"):
            safe_pickle_load(path, require_signature=False, allowed_types=(dict,))


class TestDumpRefusesBeforeWriting:
    def test_a_disallowed_object_leaves_no_file_behind(self, tmp_path: Path) -> None:
        path = tmp_path / "nested" / "artifact.pkl"
        with pytest.raises(UnsafePickleError, match="disallowed types before serialization"):
            safe_pickle_dump({"tags": {"a", "b"}}, path, sign=False)
        assert not path.exists()

    def test_a_pickling_failure_becomes_a_serialization_error(self, tmp_path: Path) -> None:
        """The allow-list can be widened by a caller; a type that passes it and
        still cannot be pickled must surface as ``SerializationError`` rather
        than an arbitrary exception from deep inside ``pickle``."""

        class Unpicklable:
            def __reduce__(self) -> object:
                raise RuntimeError("refuses to be reduced")

        path = tmp_path / "artifact.pkl"
        with pytest.raises(SerializationError, match="Failed to pickle object"):
            safe_pickle_dump(Unpicklable(), path, sign=False, allowed_types=(Unpicklable,))
        assert not path.exists()

    def test_signing_writes_the_signature_beside_the_artifact(
        self, tmp_path: Path, with_key: None
    ) -> None:
        path = tmp_path / "artifact.pkl"
        written, signature_path = safe_pickle_dump({"a": 1}, path, sign=True)
        assert written == path
        assert signature_path == path.with_suffix(".pkl.sig")
        assert verify_artifact_signature(path.read_bytes(), signature_path.read_bytes())
        assert safe_pickle_load(path, require_signature=True) == {"a": 1}

    def test_signing_without_a_key_warns_and_returns_no_signature_path(
        self, tmp_path: Path, no_key: None
    ) -> None:
        """The one deliberate fail-open, and it is loud: the artifact is written
        but the caller is told it is unsigned, and no path pretends otherwise."""
        path = tmp_path / "artifact.pkl"
        with pytest.warns(UserWarning, match="written without signature"):
            written, signature_path = safe_pickle_dump({"a": 1}, path, sign=True)
        assert written == path
        assert signature_path is None
        assert path.exists()
        assert not path.with_suffix(".pkl.sig").exists()


class TestTheAllowListReachesNestedValues:
    """The defect this file was written against, pinned with the production shape.

    ``_validate_allowed`` tested allow-list membership before dispatching on the
    container type, and ``dict``/``list`` are members of ``DEFAULT_ALLOWED`` — so
    the membership test answered True for any dict or list and both recursion
    branches were unreachable for every payload that occurs in practice.
    ``safe_pickle_load`` and ``safe_pickle_dump`` both pass ``DEFAULT_ALLOWED``,
    so the check they document as their post-load control never rejected
    anything container-shaped.

    ``set`` is the case that shows why the post-load half matters at all: it is
    in neither ``DEFAULT_ALLOWED`` nor ``RestrictedUnpickler.allowed_classes``,
    yet a set of strings pickles to ``EMPTY_SET`` + ``ADDITEMS`` with no GLOBAL
    opcode, so ``find_class`` is never consulted and the payload loads. Before
    the fix it was returned to the caller.
    """

    def test_a_disallowed_value_inside_a_dict_is_refused(self) -> None:
        assert _validate_allowed({"tags": {"a"}}, DEFAULT_ALLOWED) is False

    def test_a_disallowed_value_inside_a_list_is_refused(self) -> None:
        assert _validate_allowed([{"a"}], DEFAULT_ALLOWED) is False

    def test_a_disallowed_value_at_depth_is_refused(self) -> None:
        assert _validate_allowed({"a": [{"b": (1, 2)}]}, DEFAULT_ALLOWED) is False

    def test_a_disallowed_key_is_refused(self) -> None:
        """Keys are restricted to str/int, so a tuple key is not a JSON object."""
        assert _validate_allowed({(1, 2): "value"}, DEFAULT_ALLOWED) is False

    def test_allowed_leaves_at_depth_are_accepted(self) -> None:
        """The recursion must not turn into a blanket refusal."""
        assert _validate_allowed({"a": [1, "two", None, True, 3.0]}, DEFAULT_ALLOWED) is True

    def test_a_leaf_the_caller_excluded_is_refused(self) -> None:
        """A caller narrowing the allow-list gets the narrowing it asked for."""
        assert _validate_allowed({"n": 1}, (dict, str)) is False

    def test_load_refuses_a_nested_disallowed_value(self, tmp_path: Path, with_key: None) -> None:
        """End to end: the same set that reached a caller before the fix."""
        path = tmp_path / "artifact.pkl"
        path.write_bytes(pickle.dumps({"tags": {"a", "b"}}))
        with pytest.raises(UnsafePickleError, match="disallowed types after load"):
            safe_pickle_load(path, require_signature=False)
