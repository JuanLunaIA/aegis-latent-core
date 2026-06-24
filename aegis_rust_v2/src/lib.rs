// Copyright (c) 2026 Juan Luna. All rights reserved.
// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

//! `aegis_rust` — Tier-4 PyO3 extension module.
//!
//! | Class / Function           | Replaces                           | Speedup      |
//! |----------------------------|------------------------------------|--------------|
//! | `RustForwarder`            | reqwest::blocking + Python httpx   | ~12×         |
//! | `RustWaf`                  | Python re module (WAF)             | ~25×         |
//! | `RustRateLimiter`          | Python asyncio.Lock token bucket   | ~100×        |
//! | `RustSessionStore`         | Python OrderedDict + RLock         | ~15×         |
//! | `AuditRingBuffer`          | Python asyncio.create_task         | <1 µs enqueue|
//! | `RustWal`                  | Python os.fsync() under Lock       | ~40×         |
//! | `hash_blake3` / etc.       | Python hashlib.sha256              | ~10×         |
//! | `generate_pqc_keypair`     | —                                  | ML-DSA-65    |

#![allow(clippy::useless_conversion)]

mod audit;
mod forwarder;
mod hasher;
mod ledger;
mod mmr;
mod pqc;
mod rate_limit;
mod session;
mod wal;
mod waf;

use audit::AuditRingBuffer;
use forwarder::{warmup_runtime, RustForwarder};
use hasher::{hash_audit_payload, hash_blake3, hash_sha256_fast, keyed_hash_blake3, keyed_hash_blake3_bytes};
use ledger::{blake3_hash, blake3_keyed_hash, hash_sha256, hmac_sign};
use mmr::MmrAccumulator;
use pqc::{generate_pqc_keypair, verify_pqc_signature, PqcKeypair};
use pyo3::{prelude::*, types::PyBytes, wrap_pyfunction};
use rate_limit::RustRateLimiter;
use session::RustSessionStore;
use wal::RustWal;
use waf::{RustWaf, WafResult};

/// HTTP response compatible with httpx.Response usage in the proxy.
#[pyclass]
pub struct HttpResponse {
    pub status_code: i32,
    pub content: Vec<u8>,
    pub headers: Vec<(String, String)>,
}

#[pymethods]
impl HttpResponse {
    #[getter]
    fn status_code(&self) -> i32 {
        self.status_code
    }

    #[getter]
    fn content<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.content)
    }

    fn json(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let json_mod = py.import("json")?;
        let text = std::str::from_utf8(&self.content).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string())
        })?;
        Ok(json_mod.call_method1("loads", (text,))?.unbind())
    }

    fn headers_dict(&self, py: Python<'_>) -> PyResult<Py<pyo3::types::PyDict>> {
        let dict = pyo3::types::PyDict::new(py);
        for (k, v) in &self.headers {
            dict.set_item(k, v)?;
        }
        Ok(dict.unbind())
    }

    #[getter]
    fn headers(&self, py: Python<'_>) -> PyResult<Py<pyo3::types::PyDict>> {
        self.headers_dict(py)
    }
}

#[pymodule]
fn aegis_rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // ── Tier 1: Async HTTP forwarder ──────────────────────────────────────
    m.add_class::<RustForwarder>()?;
    m.add_class::<HttpResponse>()?;
    m.add_function(wrap_pyfunction!(warmup_runtime, m)?)?;

    // ── Tier 2: Aho-Corasick WAF ─────────────────────────────────────────
    m.add_class::<RustWaf>()?;
    m.add_class::<WafResult>()?;

    // ── Tier 3: Lock-free rate limiter ───────────────────────────────────
    m.add_class::<RustRateLimiter>()?;

    // ── Tier 4: Concurrent session store ─────────────────────────────────
    m.add_class::<RustSessionStore>()?;

    // ── Tier 5: Audit ring buffer ─────────────────────────────────────────
    m.add_class::<AuditRingBuffer>()?;

    // ── Tier 6: Memory-mapped WAL ────────────────────────────────────────
    m.add_class::<RustWal>()?;

    // ── Tier 7: BLAKE3 + ML-DSA PQC ─────────────────────────────────────
    m.add_class::<PqcKeypair>()?;
    m.add_class::<MmrAccumulator>()?;
    m.add_function(wrap_pyfunction!(generate_pqc_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(verify_pqc_signature, m)?)?;

    // Legacy SHA-256 / HMAC (backward compat)
    m.add_function(wrap_pyfunction!(hash_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(hmac_sign, m)?)?;

    // BLAKE3 fast path
    m.add_function(wrap_pyfunction!(blake3_hash, m)?)?;
    m.add_function(wrap_pyfunction!(blake3_keyed_hash, m)?)?;
    m.add_function(wrap_pyfunction!(hash_blake3, m)?)?;
    m.add_function(wrap_pyfunction!(keyed_hash_blake3, m)?)?;
    m.add_function(wrap_pyfunction!(keyed_hash_blake3_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(hash_audit_payload, m)?)?;
    m.add_function(wrap_pyfunction!(hash_sha256_fast, m)?)?;

    m.add("__version__", "3.0.0")?;
    Ok(())
}
