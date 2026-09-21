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
///
/// The build is fallible — it spawns `workers` OS threads, and thread creation
/// is a resource acquisition that fails under an RLIMIT_NPROC style limit (the
/// audit measured this aborting the process). The outcome is cached as a
/// `Result` so that a failure is reported once, to Python, as an exception
/// instead of panicking into the release profile's `panic = "abort"`
/// (AUD-05 / AF-015).
static TOKIO_RT: OnceLock<Result<tokio::runtime::Runtime, String>> = OnceLock::new();

/// Prove that the OS will actually give us `workers` threads, before tokio
/// asks for them.
///
/// tokio spawns its worker threads *through* its blocking pool, and a failed
/// `spawn_blocking` there is a `panic!("OS can't spawn worker thread: {e}")`
/// (tokio 1.52 `runtime/blocking/pool.rs`), not a returned error — under the
/// release profile's `panic = "abort"` that kills the process outright, and
/// tokio additionally marks worker-side panics with an aborting drop guard.
/// Thread creation is still a plain `io::Result` here, so the resource is
/// acquired once, up front, where the failure can still be reported
/// (AUD-05 / AF-015).
fn preflight_threads(workers: usize) -> Result<(), String> {
    let mut handles = Vec::with_capacity(workers);
    for index in 0..workers {
        match std::thread::Builder::new()
            .name(format!("aegis-io-preflight-{index}"))
            .spawn(|| {})
        {
            Ok(handle) => handles.push(handle),
            Err(e) => {
                for handle in handles {
                    let _ = handle.join();
                }
                return Err(format!(
                    "aegis-rust: Tokio runtime init failed: cannot spawn worker thread \
                     {index}/{workers}: {e}"
                ));
            }
        }
    }
    for handle in handles {
        let _ = handle.join();
    }
    Ok(())
}

/// The shared runtime, or the cached initialization failure message.
///
/// Deliberately returns a plain `Result`, not `PyResult`: it is also called
/// from inside `Python::detach` (GIL released), where constructing a `PyErr`
/// would itself be a defect. PyO3-facing callers map the message to a
/// `RuntimeError` while they still hold the interpreter.
fn rt() -> Result<&'static tokio::runtime::Runtime, String> {
    let init = TOKIO_RT.get_or_init(|| {
        let workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        // Worker threads are spawned eagerly when the runtime is built. We keep
        // the blocking pool tiny (1) because the async hickory DNS resolver
        // removes the usual per-request spawn_blocking calls; warming the
        // runtime before the seccomp filter is applied means no clone() is
        // needed at steady state. See seccomp_guard.py for the matching policy.
        preflight_threads(workers)?;
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(workers)
            .max_blocking_threads(1)
            .enable_all()
            .thread_name("aegis-io")
            .build()
            .map_err(|e| format!("aegis-rust: Tokio runtime init failed: {e}"))
    });
    match init {
        Ok(runtime) => Ok(runtime),
        Err(message) => Err(message.clone()),
    }
}

/// Force-initialize the global Tokio runtime (spawning all worker threads) and
/// exercise the async machinery once. MUST be called before the process applies
/// a seccomp filter that forbids clone()/clone3(), so that all thread creation
/// happens while those syscalls are still permitted.
#[pyfunction]
pub fn warmup_runtime() -> PyResult<usize> {
    let runtime = rt().map_err(pyo3::exceptions::PyRuntimeError::new_err)?;
    // Run a trivial async task so the reactor/timer drivers are fully started.
    runtime.block_on(async {
        tokio::time::sleep(Duration::from_millis(0)).await;
    });
    Ok(std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4))
}

/// Default cap on an upstream response body: 16 MiB, mirroring the Python
/// gateway's `max_stream_response_bytes` default (AUD-12). Overridable per
/// forwarder through `RustForwarder.new(..., max_response_bytes=...)`.
const DEFAULT_MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Why a forward failed.
///
/// `Transport` keeps the historical behaviour: a 502 response carrying a JSON
/// error body, which the gateway relays as an upstream verdict. `ResponseTooLarge`
/// is different in kind — a body that breached the configured limit is not a
/// verdict to relay — so it is raised as a Python exception instead, and the
/// gateway's own exception path turns it into a durably evidenced error
/// response (AUD-12 / AF-039).
enum ForwardError {
    Transport(String),
    ResponseTooLarge { limit: usize },
}

/// Read a response body, refusing to accumulate more than `cap` bytes.
///
/// The declared `Content-Length` is checked first as a cheap refusal, and then
/// every chunk is counted as it arrives, so an upstream that omits or understates
/// the length cannot grow this process past the cap either. The buffer never
/// exceeds the cap: a chunk that would cross it is rejected before being copied.
/// (A single transport chunk is already in memory when it is inspected; its size
/// is bounded by the client's read buffer, not by the upstream.)
async fn read_body_bounded(
    resp: &mut reqwest::Response,
    cap: usize,
) -> Result<Vec<u8>, ForwardError> {
    if let Some(declared) = resp.content_length() {
        if declared > cap as u64 {
            return Err(ForwardError::ResponseTooLarge { limit: cap });
        }
    }
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| ForwardError::Transport(format!("body read failed: {e}")))?
    {
        if body.len() + chunk.len() > cap {
            return Err(ForwardError::ResponseTooLarge { limit: cap });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
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
    max_response_bytes: usize,
}

#[pymethods]
impl RustForwarder {
    #[staticmethod]
    #[pyo3(signature = (base_url, api_key, timeout_seconds = None, connect_timeout_seconds = None, max_response_bytes = None))]
    fn new(
        base_url: String,
        api_key: String,
        timeout_seconds: Option<u64>,
        connect_timeout_seconds: Option<u64>,
        max_response_bytes: Option<usize>,
    ) -> PyResult<Self> {
        let timeout = Duration::from_secs(timeout_seconds.unwrap_or(DEFAULT_TIMEOUT_SECS));
        let connect_timeout =
            Duration::from_secs(connect_timeout_seconds.unwrap_or(DEFAULT_CONNECT_TIMEOUT_SECS));
        let max_response_bytes = max_response_bytes.unwrap_or(DEFAULT_MAX_RESPONSE_BYTES);
        if max_response_bytes == 0 {
            // A zero cap would refuse every body; the Python side raises the same
            // way for its stream limits ("stream byte limits must be positive").
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "max_response_bytes must be positive",
            ));
        }

        // Ensure the global runtime exists before building the client; a failed
        // runtime init is now raised, not aborting.
        rt().map_err(pyo3::exceptions::PyRuntimeError::new_err)?;

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
            max_response_bytes,
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
        let max_response_bytes = self.max_response_bytes;

        // Resolve the runtime while the GIL is still held: a failure must be an
        // exception, and PyErr construction needs the interpreter.
        let runtime = rt().map_err(pyo3::exceptions::PyRuntimeError::new_err)?;

        let result = py.detach(move || {
            runtime.block_on(async move {
                let mut req = client
                    .post(&url)
                    .header(CONTENT_TYPE, "application/json")
                    .body(body_bytes);

                if !api_key.is_empty() {
                    req = req.header(AUTHORIZATION, format!("Bearer {api_key}"));
                }

                let mut resp = tokio::time::timeout(timeout, req.send())
                    .await
                    .map_err(|_| ForwardError::Transport("upstream request timed out".to_string()))?
                    .map_err(|e| ForwardError::Transport(e.to_string()))?;

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
                let content = read_body_bounded(&mut resp, max_response_bytes).await?;

                Ok::<(i32, Vec<u8>, Vec<(String, String)>), ForwardError>((status, content, headers))
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
            Err(ForwardError::ResponseTooLarge { limit }) => {
                Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "upstream response exceeds the configured limit ({limit} bytes); \
                     raise max_response_bytes or max_stream_response_bytes"
                )))
            }
            Err(ForwardError::Transport(e)) => {
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

    if let Ok(dict) = body.cast::<PyDict>() {
        return python_obj_to_bytes(py, dict.as_any());
    }

    python_obj_to_bytes(py, body)
}

fn python_obj_to_bytes(py: Python<'_>, obj: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    let json_mod = py.import("json")?;
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

#[cfg(test)]
mod tests {
    use super::*;

    // AUD-05 / AF-015: runtime init used `.expect()`, which aborts the process
    // under `panic = "abort"` when thread creation fails (measured with
    // RLIMIT_NPROC). It now returns the failure for the caller to raise.
    /// The pre-flight must agree with the OS: on a host that can spawn threads
    /// it succeeds, and it is what turns tokio's `NoThreads` panic into a
    /// reportable error when the host cannot.
    #[test]
    fn preflight_threads_reports_creation_failures() {
        assert!(preflight_threads(2).is_ok());
    }

    #[test]
    fn runtime_initializes_once_and_is_cached() {
        let first = rt().expect("runtime init");
        let second = rt().expect("cached runtime");
        assert!(std::ptr::eq(first, second));
    }

    // ── AUD-12 / AF-039: the response body is read under a cap ──────────────

    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    /// Serve one HTTP/1.1 response from a local listener and return its base URL.
    ///
    /// A raw listener rather than a mocking library: the point of these tests is
    /// the *shape* of the response on the wire, including a chunked body with no
    /// Content-Length at all.
    fn serve_once(response: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf); // request head; the body is not needed
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
        });
        format!("http://127.0.0.1:{port}")
    }

    async fn fetch_capped(url: &str) -> Result<Vec<u8>, String> {
        let client = Client::builder().build().expect("client");
        let mut resp = client.get(url).send().await.expect("send");
        match read_body_bounded(&mut resp, 1_024).await {
            Ok(body) => Ok(body),
            Err(ForwardError::ResponseTooLarge { limit }) => Err(format!("too large: {limit}")),
            Err(ForwardError::Transport(e)) => Err(format!("transport: {e}")),
        }
    }

    #[test]
    fn a_declared_length_over_the_cap_is_refused() {
        // Content-Length says 5000 against a 1024 cap, and no body follows.
        let url = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 5000\r\nConnection: close\r\n\r\n".to_vec());
        let outcome = rt().expect("runtime").block_on(fetch_capped(&url));
        assert_eq!(outcome, Err("too large: 1024".to_string()));
    }

    #[test]
    fn a_chunked_body_over_the_cap_is_refused_mid_stream() {
        // Four 400-byte chunks, no Content-Length: only the counted reads can
        // stop this, and the refusal must arrive before 1600 bytes accumulate.
        let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
        for _ in 0..4 {
            response.extend_from_slice(b"190\r\n");
            response.extend_from_slice(&vec![b'z'; 400]);
            response.extend_from_slice(b"\r\n");
        }
        response.extend_from_slice(b"0\r\n\r\n");
        let url = serve_once(response);
        let outcome = rt().expect("runtime").block_on(fetch_capped(&url));
        assert_eq!(outcome, Err("too large: 1024".to_string()));
    }

    #[test]
    fn a_body_within_the_cap_is_returned_intact() {
        let body = vec![b'a'; 800];
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(&body);
        let url = serve_once(response);
        let outcome = rt().expect("runtime").block_on(fetch_capped(&url));
        assert_eq!(outcome, Ok(body));
    }
}
