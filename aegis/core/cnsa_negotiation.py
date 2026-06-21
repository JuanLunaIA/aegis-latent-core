# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.cnsa_negotiation — NSA Suite B / CNSA 2.0 algorithm negotiation.

Implements policy-driven cryptographic algorithm negotiation aligned to the
U.S. National Security Agency's Commercial National Security Algorithm (CNSA)
suites:

* **Suite B** (legacy) — ECDH/ECDSA P-256 & P-384, AES-128/256, SHA-256/384.
* **CNSA 1.0** — ECDH/ECDSA P-384, RSA-3072, AES-256, SHA-384 (classical,
  192-bit-equivalent floor).
* **CNSA 2.0** — quantum-resistant: ML-KEM (FIPS 203), ML-DSA (FIPS 204),
  LMS/XMSS for firmware signing, AES-256, SHA-384/512.

Given a peer-offered algorithm list, :class:`CNSANegotiator` selects, per
category (key establishment, signature, symmetric, hash), the strongest
mutually-supported algorithm that is approved for the required suite, and
reports every rejected offer with a reason.  This lets a deployment that
*mandates* a particular suite refuse to negotiate down to a non-compliant
algorithm rather than silently accepting it.

Usage::

    negotiator = CNSANegotiator(required_suite=CNSASuite.CNSA_2_0)
    result = negotiator.negotiate([
        "ML-KEM-1024", "ECDH-P384", "ML-DSA-87",
        "AES-256-GCM", "AES-128-GCM", "SHA-384",
    ])
    if result.compliant:
        use(result.selected)  # {"key_exchange": "ML-KEM-1024", ...}
    else:
        reject(result.reason)
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class CNSASuite(enum.Enum):
    """NSA cryptographic suite generations, ordered weakest → strongest mandate."""

    SUITE_B = "suite_b"
    CNSA_1_0 = "cnsa_1_0"
    CNSA_2_0 = "cnsa_2_0"


class AlgorithmCategory(enum.Enum):
    """Cryptographic primitive categories negotiated independently."""

    KEY_EXCHANGE = "key_exchange"
    SIGNATURE = "signature"
    SYMMETRIC = "symmetric"
    HASH = "hash"


@dataclass(frozen=True)
class Algorithm:
    """A registered cryptographic algorithm and its suite membership.

    Attributes
    ----------
    name:
        Canonical algorithm name (e.g. ``"ML-KEM-1024"``).
    category:
        The :class:`AlgorithmCategory` this algorithm satisfies.
    security_bits:
        Classical security strength in bits (used to rank candidates).
    suites:
        The set of CNSA suites that approve this algorithm.
    quantum_resistant:
        True for post-quantum algorithms (ML-KEM, ML-DSA, LMS, XMSS).
    """

    name: str
    category: AlgorithmCategory
    security_bits: int
    suites: frozenset[CNSASuite]
    quantum_resistant: bool = False

    def approved_for(self, suite: CNSASuite) -> bool:
        return suite in self.suites


# ── Approved algorithm registry ────────────────────────────────────────────────
# Source: NSA CNSA Suite (2016, Suite B successor), CNSA 1.0, and CNSA 2.0 (2022).

_B = CNSASuite.SUITE_B
_C1 = CNSASuite.CNSA_1_0
_C2 = CNSASuite.CNSA_2_0
_KX = AlgorithmCategory.KEY_EXCHANGE
_SIG = AlgorithmCategory.SIGNATURE
_SYM = AlgorithmCategory.SYMMETRIC
_HASH = AlgorithmCategory.HASH

_REGISTRY: tuple[Algorithm, ...] = (
    # ── Key establishment ──
    Algorithm("ECDH-P256", _KX, 128, frozenset({_B})),
    Algorithm("ECDH-P384", _KX, 192, frozenset({_B, _C1})),
    Algorithm("ML-KEM-768", _KX, 192, frozenset({_C2}), quantum_resistant=True),
    Algorithm("ML-KEM-1024", _KX, 256, frozenset({_C2}), quantum_resistant=True),
    # ── Digital signatures ──
    Algorithm("ECDSA-P256", _SIG, 128, frozenset({_B})),
    Algorithm("ECDSA-P384", _SIG, 192, frozenset({_B, _C1})),
    Algorithm("RSA-3072", _SIG, 128, frozenset({_C1})),
    Algorithm("ML-DSA-65", _SIG, 192, frozenset({_C2}), quantum_resistant=True),
    Algorithm("ML-DSA-87", _SIG, 256, frozenset({_C2}), quantum_resistant=True),
    Algorithm("LMS", _SIG, 256, frozenset({_C2}), quantum_resistant=True),
    Algorithm("XMSS", _SIG, 256, frozenset({_C2}), quantum_resistant=True),
    # ── Symmetric encryption ──
    Algorithm("AES-128-GCM", _SYM, 128, frozenset({_B})),
    Algorithm("AES-256-GCM", _SYM, 256, frozenset({_B, _C1, _C2})),
    # ── Hashing ──
    Algorithm("SHA-256", _HASH, 128, frozenset({_B})),
    Algorithm("SHA-384", _HASH, 192, frozenset({_B, _C1, _C2})),
    Algorithm("SHA-512", _HASH, 256, frozenset({_C2})),
)

# Curated aliases → canonical name (case/separator-insensitive lookup is applied
# on top of this for free; these handle genuinely different spellings).
_ALIASES: dict[str, str] = {
    "kyber-768": "ML-KEM-768",
    "crystals-kyber-768": "ML-KEM-768",
    "kyber-1024": "ML-KEM-1024",
    "crystals-kyber-1024": "ML-KEM-1024",
    "dilithium-3": "ML-DSA-65",
    "crystals-dilithium-3": "ML-DSA-65",
    "dilithium-5": "ML-DSA-87",
    "crystals-dilithium-5": "ML-DSA-87",
    "ecdh-secp256r1": "ECDH-P256",
    "ecdh-secp384r1": "ECDH-P384",
    "ecdsa-secp256r1": "ECDSA-P256",
    "ecdsa-secp384r1": "ECDSA-P384",
    "aes-128-gcm-256": "AES-128-GCM",
    "aes256-gcm": "AES-256-GCM",
    "aes128-gcm": "AES-128-GCM",
}


def _normalise(name: str) -> str:
    """Uppercase and strip separators for tolerant matching."""
    return "".join(ch for ch in name.upper() if ch.isalnum())


# Build canonical lookup: normalized form → Algorithm
_BY_NORMALISED: dict[str, Algorithm] = {}
for _algo in _REGISTRY:
    _BY_NORMALISED[_normalise(_algo.name)] = _algo
for _alias, _canonical in _ALIASES.items():
    _target = next(a for a in _REGISTRY if a.name == _canonical)
    _BY_NORMALISED[_normalise(_alias)] = _target


@dataclass
class NegotiationResult:
    """Outcome of a CNSA algorithm negotiation.

    Attributes
    ----------
    suite:
        The required suite this negotiation targeted (value string).
    compliant:
        True only when every category resolved to an approved algorithm.
    selected:
        Mapping of category value → selected canonical algorithm name.
    rejected:
        List of ``(offered_name, reason)`` for every rejected offer.
    missing_categories:
        Category values for which no compliant offer was found.
    reason:
        Human-readable audit summary.
    """

    suite: str
    compliant: bool = False
    selected: dict[str, str] = field(default_factory=dict)
    rejected: list[tuple[str, str]] = field(default_factory=list)
    missing_categories: list[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "suite": self.suite,
            "compliant": self.compliant,
            "selected": dict(self.selected),
            "rejected": [(n, r) for n, r in self.rejected],
            "missing_categories": list(self.missing_categories),
            "reason": self.reason,
        }


class CNSANegotiator:
    """Policy-driven NSA Suite B / CNSA algorithm negotiator.

    Parameters
    ----------
    required_suite:
        The suite a peer must satisfy.  Algorithms not approved for this suite
        are rejected.  Default :attr:`CNSASuite.CNSA_2_0` (quantum-resistant).
    mandate_quantum_resistant:
        When True, additionally require that the selected key-exchange and
        signature algorithms are post-quantum (``quantum_resistant=True``),
        regardless of suite.  For ``CNSA_2_0`` this is already implied.
    required_categories:
        Categories that MUST resolve for the negotiation to be compliant.
        Defaults to all four categories.
    """

    def __init__(
        self,
        required_suite: CNSASuite = CNSASuite.CNSA_2_0,
        mandate_quantum_resistant: bool = False,
        required_categories: set[AlgorithmCategory] | None = None,
    ) -> None:
        self.required_suite = required_suite
        self._mandate_qr = mandate_quantum_resistant
        self._required_categories = required_categories or set(AlgorithmCategory)

    # ── Introspection ──────────────────────────────────────────────────────────

    def is_approved(self, algorithm: str) -> bool:
        """Return True if *algorithm* is approved for the required suite."""
        algo = self.resolve(algorithm)
        if algo is None:
            return False
        if not algo.approved_for(self.required_suite):
            return False
        if self._mandate_qr and algo.category in (_KX, _SIG):
            return algo.quantum_resistant
        return True

    def resolve(self, algorithm: str) -> Algorithm | None:
        """Resolve an offered name (alias-aware) to a registered Algorithm."""
        return _BY_NORMALISED.get(_normalise(algorithm))

    def approved_algorithms(
        self, category: AlgorithmCategory | None = None
    ) -> list[str]:
        """List canonical names approved for the required suite (optionally
        filtered to a single *category*), strongest first."""
        out = [
            a
            for a in _REGISTRY
            if a.approved_for(self.required_suite)
            and (category is None or a.category == category)
            and not (self._mandate_qr and a.category in (_KX, _SIG) and not a.quantum_resistant)
        ]
        out.sort(key=lambda a: a.security_bits, reverse=True)
        return [a.name for a in out]

    # ── Negotiation ────────────────────────────────────────────────────────────

    def negotiate(self, peer_offered: list[str]) -> NegotiationResult:
        """Negotiate the strongest compliant algorithm per required category.

        Parameters
        ----------
        peer_offered:
            Algorithm names advertised by the peer (aliases accepted).
        """
        result = NegotiationResult(suite=self.required_suite.value)

        # Bucket offers by category among the approved ones; collect rejects.
        best_per_category: dict[AlgorithmCategory, Algorithm] = {}
        for offered in peer_offered:
            algo = self.resolve(offered)
            if algo is None:
                result.rejected.append((offered, "unknown algorithm"))
                continue
            if not algo.approved_for(self.required_suite):
                result.rejected.append(
                    (offered, f"not approved for {self.required_suite.value}")
                )
                continue
            if self._mandate_qr and algo.category in (_KX, _SIG) and not algo.quantum_resistant:
                result.rejected.append(
                    (offered, "quantum-resistant key exchange/signature mandated")
                )
                continue
            current = best_per_category.get(algo.category)
            if current is None or algo.security_bits > current.security_bits:
                best_per_category[algo.category] = algo

        # Resolve required categories.
        for category in self._required_categories:
            chosen = best_per_category.get(category)
            if chosen is None:
                result.missing_categories.append(category.value)
            else:
                result.selected[category.value] = chosen.name

        result.compliant = not result.missing_categories
        if result.compliant:
            result.reason = (
                f"{self.required_suite.value} negotiation succeeded: "
                f"{result.selected}"
            )
        else:
            result.reason = (
                f"{self.required_suite.value} negotiation FAILED: no compliant "
                f"offer for categories {result.missing_categories}"
            )
        return result
