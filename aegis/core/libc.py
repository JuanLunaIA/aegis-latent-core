# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.libc — the process's C library, found without starting a process.

``ctypes.util.find_library("c")`` looks libraries up on Linux by *executing*
``/sbin/ldconfig -p`` and, failing that, ``gcc`` and ``ld`` in subprocesses.
Inside the gateway that is wrong three ways (REG-D83): the shipped AppArmor
profile denies the exec, so the lookup fails and strict startup refused to load
the seccomp filter; after lockdown the ``pipe2``/``clone`` it needs are outside
the syscall allowlist, so an authenticated ``GET /v1/attestation/capabilities``
killed the process; and a governed gateway should not run programs at all to
find a library it already has mapped.

``ctypes.CDLL(None)`` is ``dlopen(NULL)``: a handle to the running program,
whose symbol lookup covers every library already loaded — libc included,
since the interpreter links against it. No file is opened and nothing is run.
"""

from __future__ import annotations

import ctypes
import sys

_LIBSECCOMP = "libseccomp.so.2"


def load_libc() -> ctypes.CDLL | None:
    """Return a handle to the C library this process already uses, or None."""
    if sys.platform == "win32":
        return None
    for name in (None, "libc.so.6"):
        try:
            return ctypes.CDLL(name, use_errno=True)
        except OSError:
            continue
    return None


def libseccomp_available() -> bool:
    """Whether libseccomp can be loaded, by the same name the sandbox loads it."""
    try:
        ctypes.CDLL(_LIBSECCOMP)
    except OSError:
        return False
    return True
