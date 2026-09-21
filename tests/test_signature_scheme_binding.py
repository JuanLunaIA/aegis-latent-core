"""AUD-27 / REG-D31: the declared signature scheme is covered by the signature.

`REG-D06` fenced the label by the *shape* of the material beside it: a claim for
a tier the material cannot belong to is ``invalid``, and every scheme this build
can verify was actually verified. What it could not do was make the label itself
part of what the signature covers, because the signing path learned its scheme as
the *result* of signing.

`_sign_bound` selects the tier first and rebuilds the payload per attempt with
that tier's label appended, so a record written by this build is signed over
material that contains its own ``signature_scheme``. These tests pin four
things:

1. the binding exists — the scheme-bound payload is the one that verifies, and
   the scheme-less payload it used to sign does not;
2. it holds on all three record-creating paths, not just the ingest one;
3. it is additive — a signature made before the binding still verifies against
   the older payload shape, and such a record keeps the old, published boundary
   (its label is not anchored);
4. it closes the audit's scenario wherever a verifier for the claimed tier
   exists, demonstrated with a stand-in verifier because this build has no
   ML-DSA extension and no PKCS#11 library on the host.
"""

from __future__ import annotations

import json

import pytest

from aegis.core import crypto_audit
from aegis.core.crypto_audit import (
    CryptographicAuditLedger,
    _build_signed_payload,
    _hmac_sign,
    _hmac_verify,
    scheme_material_inconsistency,
    signed_payload_candidates_for,
    validate_signature_scheme,
)

SIGNING_KEY = "reg-d31-key"


# ── helpers ───────────────────────────────────────────────────────────────────


def _commit_forensic(wal_path, count: int = 1) -> list:
    ledger = CryptographicAuditLedger(persistence_path=str(wal_path), signing_key=SIGNING_KEY)
    try:
        for index in range(count):
            ledger.commit_forensic(
                state_id=f"s{index}",
                request_bytes=b"req",
                response_bytes=b"resp",
                tenant_id="tenant-a",
            )
        return list(ledger.chain)
    finally:
        ledger.close()


def _rewrite_wal(wal_path, **fields: str) -> None:
    lines = [line for line in open(wal_path, encoding="utf-8").read().split("\n") if line.strip()]
    out: list[str] = []
    for line in lines:
        record = json.loads(line)
        for key, value in fields.items():
            if key in record:
                record[key] = value
        out.append(json.dumps(record, separators=(",", ":")))
    with open(wal_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(out) + "\n")


def _reopen(wal_path, **ledger_kwargs) -> CryptographicAuditLedger:
    return CryptographicAuditLedger(persistence_path=str(wal_path), **ledger_kwargs)


class _StandInHsm:
    """A signing backend that behaves like a token for the parts under test.

    It answers ``scheme_label()`` from its key the way a real token does, signs
    deterministically over whatever bytes it is handed, and — like a verifier
    that holds the public key — accepts a signature only for the exact payload
    it signed. That last property is what makes it usable as a stand-in for the
    deployment's verifier: acceptance depends on the payload bytes, which is
    precisely the property AUD-27 is about.
    """

    def __init__(
        self,
        scheme: str = "pkcs11-ecdsa-sha256",
        *,
        fail: bool = False,
        label: str | None = None,
        lookup_raises: Exception | None = None,
    ) -> None:
        self.available = True
        self.scheme = scheme
        self.fail = fail
        self.label = label
        self.lookup_raises = lookup_raises
        self.signed: list[bytes] = []

    def scheme_label(self) -> str:
        if self.lookup_raises is not None:
            raise self.lookup_raises
        return self.label if self.label is not None else self.scheme

    def sign(self, data: bytes):
        if self.fail:
            raise crypto_audit.HSMUnavailableError("token session lost")
        self.signed.append(data)
        return _hmac_mac(data), "ab" * 32, self.scheme


def _hmac_mac(data: bytes) -> bytes:
    return bytes.fromhex(_hmac_sign(SIGNING_KEY, data))


class _StandInMlDsaModule:
    """Verifies ML-DSA the only way a stand-in can: against what was signed."""

    def __init__(self, signed: list[bytes]) -> None:
        self._signed = signed

    def verify_pqc_signature(self, payload: bytes, signature: bytes, public_key: bytes) -> bool:
        return payload in self._signed


# ── 1. the binding exists ─────────────────────────────────────────────────────


def test_a_new_record_signs_over_the_scheme_bound_payload(tmp_path):
    wal = tmp_path / "audit.jsonl"
    node = _commit_forensic(wal)[0]

    candidates = signed_payload_candidates_for(node)
    assert candidates[0].endswith(b"|hmac-sha256")
    assert node.signature_scheme == "hmac-sha256"

    # The signature is over the bound bytes, not the scheme-less ones: this is
    # the assertion that fails if the binding is reverted.
    assert _hmac_verify(SIGNING_KEY, candidates[0], node.signature) is True
    assert _hmac_verify(SIGNING_KEY, candidates[1], node.signature) is False
    # The annotated shape is exactly the bound one minus the label — same fields,
    # same order, nothing else moved by the binding.
    assert candidates[1] == candidates[0][: -(len("|hmac-sha256"))]

    ledger = _reopen(wal, signing_key=SIGNING_KEY)
    try:
        assert ledger.signature_status(ledger.chain[0]) == "valid"
        assert ledger.verify_integrity() == (True, None)
    finally:
        ledger.close()


def test_the_bound_label_is_the_one_the_record_declares(tmp_path):
    """The scheme in the signed bytes and the scheme on the node are one value.

    They are produced by the same selection, not compared after the fact, so a
    disagreement is not a state this build can write.
    """

    wal = tmp_path / "audit.jsonl"
    node = _commit_forensic(wal)[0]
    bound = signed_payload_candidates_for(node)[0].decode()
    assert bound.rsplit("|", 1)[1] == node.signature_scheme


# ── 2. all three record-creating paths bind ───────────────────────────────────


def test_the_rejection_path_binds_its_scheme(tmp_path):
    ledger = CryptographicAuditLedger(
        persistence_path=str(tmp_path / "audit.jsonl"), signing_key=SIGNING_KEY
    )
    try:
        node = ledger.commit_rejection(
            request_bytes=b"req", rejection_code=403, reason_category="policy"
        )
        assert node.signature_scheme == "hmac-sha256"
        assert signed_payload_candidates_for(node)[0].endswith(b"|hmac-sha256")
        assert ledger.signature_status(node) == "valid"
    finally:
        ledger.close()


def test_the_stream_terminal_path_binds_its_scheme(tmp_path):
    ledger = CryptographicAuditLedger(
        persistence_path=str(tmp_path / "audit.jsonl"), signing_key=SIGNING_KEY
    )
    try:
        node = ledger.commit_forensic_summary(
            state_id="stream-1",
            request_bytes=b"req",
            response_hash="ab" * 32,
            response_size=12,
            response_preview=b"preview",
            terminal_outcome="complete",
            final_marker_included=True,
            token_count=3,
            elapsed_seconds=0.25,
        )
        assert node.signature_scheme == "hmac-sha256"
        assert signed_payload_candidates_for(node)[0].endswith(b"|hmac-sha256")
        assert ledger.signature_status(node) == "valid"
    finally:
        ledger.close()


# ── 3. additive: pre-binding signatures still verify ──────────────────────────


def test_a_pre_binding_signature_still_verifies_and_keeps_the_old_boundary(tmp_path):
    """A record signed before the binding must not be invalidated by it.

    The signature is replaced with one over the annotated (scheme-less) payload,
    which is exactly the material the pre-binding code signed. It verifies via
    the older candidate, and the record's label is *not* anchored — the same
    relabelling that a bound record now catches still reads ``unverified`` here.
    That residual is the published boundary of ``UC-054`` (b), not a regression.
    """

    wal = tmp_path / "audit.jsonl"
    node = _commit_forensic(wal)[0]
    annotated = signed_payload_candidates_for(node)[1]

    _rewrite_wal(wal, signature=_hmac_sign(SIGNING_KEY, annotated))
    ledger = _reopen(wal, signing_key=SIGNING_KEY)
    try:
        legacy = ledger.chain[0]
        assert ledger.signature_status(legacy) == "valid"
        candidates = signed_payload_candidates_for(legacy)
        assert _hmac_verify(SIGNING_KEY, candidates[1], legacy.signature) is True
        assert _hmac_verify(SIGNING_KEY, candidates[0], legacy.signature) is False
    finally:
        ledger.close()

    # Relabel the legacy record into a tier this build cannot verify. Material
    # stays shape-consistent, so the reading is "unverified" — the boundary.
    _rewrite_wal(
        wal,
        signature_scheme="pkcs11-ecdsa-sha256",
        signature="ab" * 128,
        public_key="cd" * 128,
    )
    ledger = _reopen(wal, signing_key=SIGNING_KEY)
    try:
        relabelled = ledger.chain[0]
        assert scheme_material_inconsistency(relabelled) is None
        assert ledger.signature_status(relabelled) == "unverified"
    finally:
        ledger.close()


# ── 4. the audit's scenario, wherever a verifier for the claimed tier exists ──


def _mint_hsm_node(wal, hsm: _StandInHsm, *, bind: bool) -> None:
    """Commit one node through the stand-in token.

    ``bind=True`` is the code under test: the token signs the payload that
    carries its own label. ``bind=False`` reproduces what the pre-binding code
    did — the token signed the scheme-less payload — so the same relabelling can
    be compared across the two shapes.
    """

    ledger = CryptographicAuditLedger(persistence_path=str(wal), hsm_backend=hsm)
    try:
        node = ledger.commit_forensic(
            state_id="s0", request_bytes=b"req", response_bytes=b"resp", tenant_id="tenant-a"
        )
    finally:
        ledger.close()

    if not bind:
        annotated = _build_signed_payload(
            prev_hash=node.prev_hash,
            merkle_root=node.merkle_root,
            request_hash=node.request_hash,
            response_hash=node.response_hash,
            waf_verdict=node.waf_verdict,
            signer_name=node.signer_name,
            signature_meaning=node.signature_meaning,
            status=node.status,
        )
        hsm.signed.append(annotated)  # the token signed this in the old shape
        _rewrite_wal(wal, signature=annotated and _hmac_sign(SIGNING_KEY, annotated))


def test_a_relabelled_claim_is_caught_when_a_verifier_for_the_tier_exists(tmp_path, monkeypatch):
    """The audit's scenario: a well-shaped claim for another tier.

    The record is signed by the stand-in token as ``pkcs11-ecdsa-sha256``, then
    relabelled to ``pqc-ml-dsa`` — the same shape class (presence-only), so
    ``REG-D06`` alone reads it as ``unverified``. With the label bound and a
    verifier for the claimed tier present, the verifier is asked about the
    *relabelled* material and refuses it.
    """

    wal = tmp_path / "audit.jsonl"
    hsm = _StandInHsm()
    _mint_hsm_node(wal, hsm, bind=True)
    _rewrite_wal(wal, signature_scheme="pqc-ml-dsa")

    monkeypatch.setattr(crypto_audit, "RUST_AVAILABLE", True)
    monkeypatch.setattr(crypto_audit, "aegis_rust", _StandInMlDsaModule(hsm.signed), raising=False)

    ledger = _reopen(wal)
    try:
        node = ledger.chain[0]
        assert scheme_material_inconsistency(node) is None
        assert ledger.signature_status(node) == "invalid"
    finally:
        ledger.close()


def test_the_same_relabel_is_accepted_on_a_pre_binding_record(tmp_path, monkeypatch):
    """Control for the test above: without the binding, the relabel survives.

    Identical in every respect except that the token signed the scheme-less
    payload, which is what the pre-fix code did. The stand-in verifier accepts
    it, which is the audit's "a fabricated but well-shaped claim" — the state
    ``REG-D31`` removes for records written by this build.
    """

    wal = tmp_path / "audit.jsonl"
    hsm = _StandInHsm()
    _mint_hsm_node(wal, hsm, bind=False)
    _rewrite_wal(wal, signature_scheme="pqc-ml-dsa")

    monkeypatch.setattr(crypto_audit, "RUST_AVAILABLE", True)
    monkeypatch.setattr(crypto_audit, "aegis_rust", _StandInMlDsaModule(hsm.signed), raising=False)

    ledger = _reopen(wal)
    try:
        node = ledger.chain[0]
        assert scheme_material_inconsistency(node) is None
        assert ledger.signature_status(node) == "valid"
    finally:
        ledger.close()


# ── 5. the HSM fallback binds the tier that actually signed ───────────────────


def test_an_hsm_failure_mid_flight_binds_the_fallback_tiers_label(tmp_path):
    """A tier that fails is not the tier whose label gets bound.

    The old shape learned the scheme as the return value of a signature, so a
    failure between selection and signing was the case where the recorded label
    and the signer could drift. Now the payload is rebuilt per attempt.
    """

    wal = tmp_path / "audit.jsonl"
    hsm = _StandInHsm(fail=True)
    ledger = CryptographicAuditLedger(
        persistence_path=str(wal), signing_key=SIGNING_KEY, hsm_backend=hsm
    )
    try:
        node = ledger.commit_forensic(
            state_id="s0", request_bytes=b"req", response_bytes=b"resp", tenant_id="tenant-a"
        )
        assert node.signature_scheme == "hmac-sha256"
        assert signed_payload_candidates_for(node)[0].endswith(b"|hmac-sha256")
        assert ledger.signature_status(node) == "valid"
    finally:
        ledger.close()


def test_a_backend_without_label_introspection_pays_the_extra_sign_once(tmp_path):
    """Backends that cannot answer ``scheme_label`` learn the label by signing.

    That costs one discarded signature — once per ledger, not once per record —
    and the label learned that way is bound into the record exactly like one
    read from the key. The security property never depends on which path a
    backend takes; only the cost differs.
    """

    class _NoIntrospection:
        available = True

        def __init__(self) -> None:
            self.calls: list[bytes] = []

        def sign(self, data: bytes):
            self.calls.append(data)
            return _hmac_mac(data), "ab" * 32, "pkcs11-rsa-pss-sha256"

    wal = tmp_path / "audit.jsonl"
    backend = _NoIntrospection()
    ledger = CryptographicAuditLedger(persistence_path=str(wal), hsm_backend=backend)
    try:
        first = ledger.commit_forensic(
            state_id="s0", request_bytes=b"req", response_bytes=b"resp", tenant_id="tenant-a"
        )
        second = ledger.commit_forensic(
            state_id="s1", request_bytes=b"req", response_bytes=b"resp", tenant_id="tenant-a"
        )
    finally:
        ledger.close()

    assert [n.signature_scheme for n in (first, second)] == ["pkcs11-rsa-pss-sha256"] * 2
    assert len(backend.calls) == 3  # probe + first record, then one per record
    assert signed_payload_candidates_for(first)[0].endswith(b"|pkcs11-rsa-pss-sha256")
    assert signed_payload_candidates_for(second)[0].endswith(b"|pkcs11-rsa-pss-sha256")


def test_a_token_that_answers_a_different_label_rebinds_before_recording(tmp_path):
    """A label predicted from the key that the token then contradicts.

    The label is read before signing and checked against what the signature
    reports; a disagreement rebuilds the payload over the reported label and
    signs again, so the recorded scheme and the signed bytes still agree. The
    first signature is discarded, never recorded against the wrong label.
    """

    wal = tmp_path / "audit.jsonl"
    hsm = _StandInHsm(scheme="pkcs11-ecdsa-sha256", label="pkcs11-rsa-pss-sha256")
    ledger = CryptographicAuditLedger(persistence_path=str(wal), hsm_backend=hsm)
    try:
        node = ledger.commit_forensic(
            state_id="s0", request_bytes=b"req", response_bytes=b"resp", tenant_id="tenant-a"
        )
    finally:
        ledger.close()

    assert node.signature_scheme == "pkcs11-ecdsa-sha256"
    assert len(hsm.signed) == 2  # predicted-label payload, then the reported one
    assert hsm.signed[0].endswith(b"|pkcs11-rsa-pss-sha256")
    assert hsm.signed[1].endswith(b"|pkcs11-ecdsa-sha256")


def test_a_token_reporting_an_unknown_label_falls_back_instead_of_binding_it(tmp_path):
    """A label outside the vocabulary cannot be bound, so the tier cannot sign.

    Refusing the label means falling through to the next tier rather than
    recording a claim no verifier could ever judge.
    """

    wal = tmp_path / "audit.jsonl"
    hsm = _StandInHsm(scheme="pkcs11-quantum-v9", label="pkcs11-quantum-v9")
    ledger = CryptographicAuditLedger(
        persistence_path=str(wal), signing_key=SIGNING_KEY, hsm_backend=hsm
    )
    try:
        node = ledger.commit_forensic(
            state_id="s0", request_bytes=b"req", response_bytes=b"resp", tenant_id="tenant-a"
        )
        assert node.signature_scheme == "hmac-sha256"
        assert signed_payload_candidates_for(node)[0].endswith(b"|hmac-sha256")
        assert ledger.signature_status(node) == "valid"
    finally:
        ledger.close()


def test_a_label_lookup_that_fails_degrades_to_learning_by_signing(tmp_path):
    """Neither failure mode of ``scheme_label`` weakens the binding.

    A token that cannot answer costs one extra signature; a token whose lookup
    raises an unexpected error costs a warning and the same extra signature. In
    both cases the label that ends up in a record is one learned from a
    signature, and a tier that cannot sign at all still falls through.
    """

    wal = tmp_path / "audit.jsonl"
    hsm = _StandInHsm(scheme="pkcs11-ecdsa-sha256", lookup_raises=RuntimeError("token gone"))
    ledger = CryptographicAuditLedger(
        persistence_path=str(wal), signing_key=SIGNING_KEY, hsm_backend=hsm
    )
    try:
        node = ledger.commit_forensic(
            state_id="s0", request_bytes=b"req", response_bytes=b"resp", tenant_id="tenant-a"
        )
        assert node.signature_scheme == "pkcs11-ecdsa-sha256"
        assert signed_payload_candidates_for(node)[0].endswith(b"|pkcs11-ecdsa-sha256")
    finally:
        ledger.close()

    # A backend that cannot even hold a session raises out of the lookup, which
    # the tier treats like a signing failure: the next tier signs.
    gone = _StandInHsm(
        scheme="pkcs11-ecdsa-sha256",
        lookup_raises=crypto_audit.HSMUnavailableError("no session"),
    )
    ledger = CryptographicAuditLedger(
        persistence_path=str(tmp_path / "audit2.jsonl"),
        signing_key=SIGNING_KEY,
        hsm_backend=gone,
    )
    try:
        node = ledger.commit_forensic(
            state_id="s0", request_bytes=b"req", response_bytes=b"resp", tenant_id="tenant-a"
        )
        assert node.signature_scheme == "hmac-sha256"
    finally:
        ledger.close()


def test_an_ml_dsa_signer_that_fails_falls_through_to_the_next_tier(tmp_path):
    """A configured signer that cannot sign must not block the record.

    The tier order is a preference, not a requirement: the record is still
    written, signed by the next tier, with *that* tier's label bound.
    """

    class _BrokenSigner:
        @property
        def public_key(self) -> bytes:
            raise AssertionError("public_key must not be read when signing failed")

        def sign(self, _data: bytes) -> bytes:
            raise RuntimeError("ML-DSA unavailable")

    wal = tmp_path / "audit.jsonl"
    ledger = CryptographicAuditLedger(persistence_path=str(wal), signing_key=SIGNING_KEY)
    ledger._pqc_signer = lambda: _BrokenSigner()  # type: ignore[method-assign]
    try:
        node = ledger.commit_forensic(
            state_id="s0", request_bytes=b"req", response_bytes=b"resp", tenant_id="tenant-a"
        )
        assert node.signature_scheme == "hmac-sha256"
        assert signed_payload_candidates_for(node)[0].endswith(b"|hmac-sha256")
        assert ledger.signature_status(node) == "valid"
    finally:
        ledger.close()


# ── 6. the label is held to the bound-field rules ─────────────────────────────


def test_a_label_carrying_the_delimiter_cannot_be_bound():
    """Bound fields share one rule: no delimiter, or two field lists can collide."""

    with pytest.raises(ValueError, match="not one this codebase writes"):
        _build_signed_payload(
            prev_hash="a",
            merkle_root="b",
            request_hash="c",
            response_hash="d",
            signature_scheme="evil|hmac-sha256",
        )


def test_an_empty_label_is_refused_and_omission_reproduces_the_legacy_payload():
    """Omission and emptiness are different things, and the difference is load-bearing."""

    with pytest.raises(ValueError):
        validate_signature_scheme("")

    omitted = _build_signed_payload(
        prev_hash="a", merkle_root="b", request_hash="c", response_hash="d"
    )
    assert omitted == b"a|b|c|d"
    assert validate_signature_scheme("hmac-sha256") == "hmac-sha256"
