"""Aegis Latent Core — forensic evidence gateway for LLM inference pipelines.

Two deployment shapes share one evidence format:

- **Gateway.** ``aegis`` / ``aegis-server`` run the proxy in
  :mod:`aegis.proxy.app` as a separate process the application cannot bypass.
- **Embedded.** :func:`aegis.wrap` runs the same WAF, redaction and signed
  ledger inside the calling process, for applications that hold the provider
  client themselves and cannot add a network hop.

The embedded engine constrains calls made through the client it wraps; it is
not a containment boundary against the process it runs in. See
:mod:`aegis.embedded`.
"""

__version__ = "5.0.2"

from aegis.embedded import AegisBlockedError, AegisEmbedded, AegisEmbeddedError, wrap

__all__ = [
    "AegisBlockedError",
    "AegisEmbedded",
    "AegisEmbeddedError",
    "__version__",
    "wrap",
]

# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
