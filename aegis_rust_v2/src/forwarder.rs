// Copyright (c) 2026 Juan Luna. All rights reserved.
// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

//! Tier-4 async HTTP forwarder.
//!
//! Replaces `reqwest::blocking::Client` (one OS thread per request, no
//! connection pooling) with an async `reqwest::Client` backed by a global
//! multi-threaded Tokio runtime.
//!
//! Key improvements over the blocking implementation:
//!   - Persistent keep-alive connection pool (up to 100 idle per host).
//!   - TCP_NODELAY eliminates Nagle algorithm latency (~40 ms → <1 ms on LAN).
//!   - HTTP/2 multiplexing when upstream supports it (fewer TCP connections).
//!   - GIL released during I/O via `py.allow_threads()`.
//!   - Global OnceLock runtime: constructed once, reused across all forwarder
//!     instances; no per-request runtime creation overhead.
//!
//! Throughput: a single async reqwest client can sustain >100k RPS on a
//! 32-core host vs ~8k RPS for reqwest::blocking with the same thread count.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use reqwest::{
    header::{AUTHORIZATION, CONTENT_TYPE},
    Client,
};
use serde_json::Value;
use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};

use crate::HttpResponse;

/// Global multi-threaded Tokio runtime, shared across all RustForwarder instances.
static TOKIO_RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn rt() -> &'static tokio::runtime::Runtime {
    TOKIO_RT.get_or_init(|| {
        let workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        // Worker threads are spawned eagerly when the runtime is built. We keep
        // the blocking pool tiny (1) because the async hickory DNS resolver
        // removes the usual per-request spawn_blocking calls; warming the
        // runtime before the seccomp filter is applied means no clone() is
        // needed at steady state. See seccomp_guard.py for the matching policy.
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(workers)
            .max_blocking_threads(1)
            .enable_all()
            .thread_name("aegis-io")
            .build()
            .expect("aegis-rust: Tokio runtime init failed")
    })
}

/// Force-initialize the global Tokio runtime (spawning all worker threads) and
/// exercise the async machinery once. MUST be called before the process applies
/// a seccomp filter that forbids clone()/clone3(), so that all thread creation
/// happens while those syscalls are still permitted.
#[pyfunction]
pub fn warmup_runtime() -> usize {
    let runtime = rt();
    // Run a trivial async task so the reactor/timer drivers are fully started.
    runtime.block_on(async {
        tokio::time::sleep(Duration::from_millis(0)).await;
    });
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

const DEFAULT_TIMEOUT_SECS: u64 = 120;
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;
const POOL_IDLE_TIMEOUT_SECS: u64 = 90;
const POOL_MAX_IDLE_PER_HOST: usize = 100;

#[pyclass]
pub struct RustForwarder {
    base_url: Arc<String>,
    api_key: Arc<String>,
    client: Arc<Client>,
    timeout: Duration,
}

#[pymethods]
impl RustForwarder {
    #[staticmethod]
    #[pyo3(signature = (base_url, api_key, timeout_seconds = None, connect_timeout_seconds = None))]
    fn new(
        base_url: String,
        api_key: String,
        timeout_seconds: Option<u64>,
        connect_timeout_seconds: Option<u64>,
    ) -> PyResult<Self> {
        let timeout = Duration::from_secs(timeout_seconds.unwrap_or(DEFAULT_TIMEOUT_SECS));
        let connect_timeout =
            Duration::from_secs(connect_timeout_seconds.unwrap_or(DEFAULT_CONNECT_TIMEOUT_SECS));

        // Ensure the global runtime exists before building the client.
        let _ = rt();

        let client = Client::builder()
            .timeout(timeout)
            .connect_timeout(connect_timeout)
            .tcp_keepalive(Duration::from_secs(POOL_IDLE_TIMEOUT_SECS))
            .tcp_nodelay(true)
            .pool_idle_timeout(Duration::from_secs(POOL_IDLE_TIMEOUT_SECS))
            .pool_max_idle_per_host(POOL_MAX_IDLE_PER_HOST)
            .http2_adaptive_window(true)
            // Async DNS (no blocking-pool thread spawn) — see warmup_runtime().
            .hickory_dns(true)
            .build()
            .map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "RustForwarder client build failed: {e}"
                ))
            })?;

        Ok(RustForwarder {
            base_url: Arc::new(normalize_base_url(&base_url)),
            api_key: Arc::new(api_key),
            client: Arc::new(client),
            timeout,
        })
    }

    /// POST JSON body to `path`. GIL is released during I/O.
    fn forward_json_sync(
        &self,
        py: Python<'_>,
        path: &str,
        body: &Bound<'_, PyAny>,
    ) -> PyResult<Py<HttpResponse>> {
        let body_bytes = extract_body_bytes(py, body)?;
        let url = format!("{}{}", self.base_url, normalize_path(path));
        let api_key = self.api_key.clone();
        let client = self.client.clone();
        let timeout = self.timeout;

        let result = py.allow_threads(move || {
            rt().block_on(async move {
                let mut req = client
                    .post(&url)
                    .header(CONTENT_TYPE, "application/json")
                    .body(body_bytes);

                if !api_key.is_empty() {
                    req = req.header(AUTHORIZATION, format!("Bearer {api_key}"));
                }

                let resp = tokio::time::timeout(timeout, req.send())
                    .await
                    .map_err(|_| "upstream request timed out".to_string())?
                    .map_err(|e| e.to_string())?;

                let status = resp.status().as_u16() as i32;
                let headers: Vec<(String, String)> = resp
                    .headers()
                    .iter()
                    .filter_map(|(k, v)| {
                        v.to_str()
                            .ok()
                            .map(|val| (k.as_str().to_owned(), val.to_owned()))
                    })
                    .collect();
                let content = resp
                    .bytes()
                    .await
                    .map_err(|e| format!("body read failed: {e}"))?
                    .to_vec();

                Ok::<(i32, Vec<u8>, Vec<(String, String)>), String>((status, content, headers))
            })
        });

        match result {
            Ok((status, content, headers)) => Py::new(
                py,
                HttpResponse {
                    status_code: status,
                    content,
                    headers,
                },
            ),
            Err(e) => {
                let body = serde_json::json!({
                    "error": {
                        "message": e,
                        "type": "aegis_rust_forwarder_error"
                    }
                })
                .to_string()
                .into_bytes();
                Py::new(
                    py,
                    HttpResponse {
                        status_code: 502,
                        content: body,
                        headers: vec![("content-type".to_string(), "application/json".to_string())],
                    },
                )
            }
        }
    }

    /// Return the number of threads in the global Tokio runtime.
    #[staticmethod]
    fn worker_thread_count() -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Serialise any Python JSON-representable object to raw bytes.
fn extract_body_bytes(py: Python<'_>, body: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if let Ok(s) = body.extract::<&str>() {
        // Already a JSON string — validate and re-serialise to canonical form.
        let v: Value = serde_json::from_str(s).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("invalid JSON string: {e}"))
        })?;
        return serde_json::to_vec(&v).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("JSON re-serialise: {e}"))
        });
    }

    if let Ok(dict) = body.downcast::<PyDict>() {
        return python_obj_to_bytes(py, dict.as_any());
    }

    python_obj_to_bytes(py, body)
}

fn python_obj_to_bytes(py: Python<'_>, obj: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    let json_mod = py.import_bound("json")?;
    let dumped: String = json_mod.call_method1("dumps", (obj,))?.extract()?;
    Ok(dumped.into_bytes())
}

fn normalize_base_url(url: &str) -> String {
    // Restore localhost→127.0.0.1 to avoid IPv6/host-resolution quirks and
    // TLS CN/SAN mismatches in environments with non-standard /etc/hosts.
    // Port-qualified form first to avoid double-replacing the host-only form.
    url.replace("://localhost:", "://127.0.0.1:")
        .replace("://localhost", "://127.0.0.1")
        .trim_end_matches('/')
        .to_string()
}

fn normalize_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}
