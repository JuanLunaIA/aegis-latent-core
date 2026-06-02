// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
#![allow(clippy::useless_conversion)] // PyO3 PyResult<T> vs Py<T> false positives

mod forwarder;
mod ledger;
mod mmr;
mod pqc;

use forwarder::RustForwarder;
use mmr::MmrAccumulator;
use pqc::{generate_pqc_keypair, verify_pqc_signature, PqcKeypair};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use pyo3::wrap_pyfunction;

/// HTTP response compatible with httpx.Response usage in the proxy.
#[pyclass]
pub struct HttpResponse {
    status_code: i32,
    content: Vec<u8>,
    headers: Vec<(String, String)>,
}

#[pymethods]
impl HttpResponse {
    #[getter]
    fn status_code(&self) -> i32 {
        self.status_code
    }

    #[getter]
    fn content<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.content)
    }

    fn json(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let json_mod = py.import_bound("json")?;
        let text = std::str::from_utf8(&self.content)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        let obj = json_mod.call_method1("loads", (text,))?;
        Ok(obj.unbind())
    }

    fn headers_dict(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let dict = PyDict::new_bound(py);
        for (k, v) in &self.headers {
            dict.set_item(k, v)?;
        }
        Ok(dict.unbind())
    }

    #[getter]
    fn headers(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        self.headers_dict(py)
    }
}

#[pymodule]
fn aegis_rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<RustForwarder>()?;
    m.add_class::<HttpResponse>()?;
    m.add_class::<PqcKeypair>()?;
    m.add_class::<MmrAccumulator>()?;
    m.add_function(wrap_pyfunction!(generate_pqc_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(verify_pqc_signature, m)?)?;
    m.add_function(wrap_pyfunction!(ledger::hash_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(ledger::hmac_sign, m)?)?;
    m.add("__version__", "2.0.0")?;
    Ok(())
}
