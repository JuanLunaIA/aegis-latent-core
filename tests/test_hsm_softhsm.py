# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""``HSMSigningBackend`` against a real PKCS#11 stack (SoftHSM2), not a mock.

``tests/test_hsm.py`` injects fake PKCS#11 objects. Its mock invented a
``pkcs11.mechanisms.RSA_PKCS_PSS_PARAMS`` class that the real library does not have, so
RSA signing failed on every real token while the suite stayed green. This module runs the
adapter against SoftHSM2 in a subprocess (so the token directory is set before the
library initialises) and verifies each signature independently with ``cryptography``.

Skipped when SoftHSM2 or ``python-pkcs11`` is not installed. It shows the adapter works
against one software token. It does not establish interoperability with any hardware HSM
or cloud HSM, key non-exportability, or certification.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

SOFTHSM_LIB = next(
    (p for p in ("/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so") if Path(p).exists()),
    None,
)  # fmt: skip

pytestmark = pytest.mark.skipif(
    shutil.which("softhsm2-util") is None or SOFTHSM_LIB is None,
    reason="SoftHSM2 is not installed",
)

_PROGRAM = textwrap.dedent(
    """
    import sys
    import pkcs11
    from pkcs11 import KeyType, Mechanism
    from aegis.core.hsm import HSMSigningBackend

    lib_path, kind = sys.argv[1], sys.argv[2]
    lib = pkcs11.lib(lib_path)
    token = next(lib.get_tokens(token_label="aegis-test"))
    with token.open(rw=True, user_pin="4321") as session:
        if kind == "rsa":
            pub, priv = session.generate_keypair(KeyType.RSA, 2048, label="aegis-signing-key", store=True)
        else:
            params = session.create_domain_parameters(
                KeyType.EC, {pkcs11.Attribute.EC_PARAMS: pkcs11.util.ec.encode_named_curve_parameters("secp256r1")}, local=True
            )
            pub, priv = params.generate_keypair(label="aegis-signing-key", store=True)
    slot = next(s for s in lib.get_slots(token_present=True) if s.get_token().label == "aegis-test")
    backend = HSMSigningBackend(lib_path, slot_id=slot.slot_id, pin="4321", key_label="aegis-signing-key", token_label="aegis-test")
    assert backend.available
    data = b"aegis softhsm evidence node"
    sig, pub_hex, scheme = backend.sign(data)
    backend.close()

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    key = serialization.load_der_public_key(bytes.fromhex(pub_hex))
    tampered = data[:-1] + b"X"
    if kind == "rsa":
        pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
        verify = lambda message: key.verify(sig, message, pss, hashes.SHA256())
    else:
        half = len(sig) // 2
        der = encode_dss_signature(int.from_bytes(sig[:half], "big"), int.from_bytes(sig[half:], "big"))
        verify = lambda message: key.verify(der, message, ec.ECDSA(hashes.SHA256()))
    verify(data)
    try:
        verify(tampered)
    except InvalidSignature:
        print("RESULT", scheme, "verified", "tampered-rejected")
    else:
        print("RESULT", scheme, "verified", "TAMPERED-ACCEPTED")
    """
)


def _run(tmp_path: Path, kind: str) -> list[str]:
    tokens = tmp_path / "tokens"
    tokens.mkdir()
    conf = tmp_path / "softhsm2.conf"
    conf.write_text(
        f"directories.tokendir = {tokens}\nobjectstore.backend = file\nlog.level = ERROR\n"
    )
    env = {**os.environ, "SOFTHSM2_CONF": str(conf)}
    subprocess.run(  # noqa: S603  # nosec B603 B607 - fixed argv, shell=False
        ["softhsm2-util", "--init-token", "--free", "--label", "aegis-test", "--so-pin", "1234", "--pin", "4321"],
        check=True, capture_output=True, env=env,
    )  # fmt: skip
    out = subprocess.run(  # noqa: S603  # nosec B603 - this interpreter, shell=False
        [sys.executable, "-c", _PROGRAM, str(SOFTHSM_LIB), kind],
        check=True, capture_output=True, text=True, env=env, timeout=120,
    )  # fmt: skip
    return out.stdout.strip().splitlines()[-1].split()


# Verification runs inside the subprocess: a clean interpreter, so a test that patches
# ``sys.modules`` or ``cryptography`` earlier in the session cannot change the outcome.
def test_rsa_pss_signature_from_a_real_token_verifies_independently(tmp_path: Path) -> None:
    pytest.importorskip("pkcs11")
    assert _run(tmp_path, "rsa") == [
        "RESULT",
        "pkcs11-rsa-pss-sha256",
        "verified",
        "tampered-rejected",
    ]


def test_ecdsa_signature_from_a_token_without_ecdsa_sha256_verifies_independently(
    tmp_path: Path,
) -> None:
    pytest.importorskip("pkcs11")
    assert _run(tmp_path, "ec") == [
        "RESULT",
        "pkcs11-ecdsa-sha256",
        "verified",
        "tampered-rejected",
    ]
