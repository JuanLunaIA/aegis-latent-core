// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
use pyo3::prelude::*;
use pyo3::types::PyDict;
use reqwest::blocking::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde_json::Value;
use std::time::Duration;

use crate::HttpResponse;

const DEFAULT_TIMEOUT_SECS: u64 = 120;
const CONNECT_TIMEOUT_SECS: u64 = 10;

#[pyclass]
pub struct RustForwarder {
    base_url: String,
    api_key: String,
    client: Client,
}

#[pymethods]
impl RustForwarder {
    #[staticmethod]
    #[pyo3(signature = (base_url, api_key, timeout_seconds=None, connect_timeout_seconds=None))]
    fn new(
        base_url: String,
        api_key: String,
        timeout_seconds: Option<u64>,
        connect_timeout_seconds: Option<u64>,
    ) -> PyResult<Self> {
        let total = Duration::from_secs(timeout_seconds.unwrap_or(DEFAULT_TIMEOUT_SECS));
        let connect = Duration::from_secs(connect_timeout_seconds.unwrap_or(CONNECT_TIMEOUT_SECS));
        let client = Client::builder()
            .timeout(total)
            .connect_timeout(connect)
            .http1_only()
            .build()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
        Ok(RustForwarder {
            base_url: normalize_base_url(base_url.trim_end_matches('/')),
            api_key,
            client,
        })
    }

    /// POST JSON to `path` relative to base_url; returns httpx-compatible response object.
    fn forward_json_sync(&self, py: Python<'_>, path: &str, body: &Bound<'_, PyAny>) -> PyResult<Py<HttpResponse>> {
        let json_value: Value = if let Ok(s) = body.extract::<&str>() {
            serde_json::from_str(s).map_err(json_err)?
        } else if let Ok(dict) = body.downcast::<PyDict>() {
            python_dict_to_json(py, dict)?
        } else {
            let json_mod = py.import_bound("json")?;
            let dumped = json_mod.call_method1("dumps", (body,))?;
            let s: String = dumped.extract()?;
            serde_json::from_str(&s).map_err(json_err)?
        };

        let url = format!("{}{}", self.base_url, normalize_path(path));
        let body_bytes = serde_json::to_vec(&json_value).map_err(json_err)?;
        let api_key = self.api_key.clone();
        let client = self.client.clone();

        let http_result = py.allow_threads(move || {
            let mut req = client
                .post(&url)
                .header(CONTENT_TYPE, "application/json")
                .body(body_bytes);
            if !api_key.is_empty() {
                req = req.header(AUTHORIZATION, format!("Bearer {api_key}"));
            }
            req.send()
        });

        match http_result {
            Ok(resp) => {
                let status = resp.status().as_u16() as i32;
                let headers = resp
                    .headers()
                    .iter()
                    .filter_map(|(k, v)| {
                        v.to_str()
                            .ok()
                            .map(|val| (k.as_str().to_string(), val.to_string()))
                    })
                    .collect();
                let content = resp.bytes().unwrap_or_default().to_vec();
                Py::new(
                    py,
                    HttpResponse {
                        status_code: status,
                        content,
                        headers,
                    },
                )
            }
            Err(e) => {
                let body = serde_json::json!({
                    "error": {
                        "message": format!("upstream request failed: {e}"),
                        "type": "aegis_rust_forwarder_error"
                    }
                });
                Py::new(
                    py,
                    HttpResponse {
                        status_code: 502,
                        content: body.to_string().into_bytes(),
                        headers: vec![("content-type".to_string(), "application/json".to_string())],
                    },
                )
            }
        }
    }
}

fn normalize_base_url(url: &str) -> String {
    url.replace("://localhost", "://127.0.0.1")
        .replace("://localhost:", "://127.0.0.1:")
}

fn normalize_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn json_err(e: serde_json::Error) -> PyErr {
    PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("invalid JSON body: {e}"))
}

fn python_dict_to_json(py: Python<'_>, dict: &Bound<'_, PyDict>) -> PyResult<Value> {
    let json_mod = py.import_bound("json")?;
    let dumped = json_mod.call_method1("dumps", (dict,))?;
    let s: String = dumped.extract()?;
    serde_json::from_str(&s).map_err(json_err)
}
