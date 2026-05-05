use pyo3::prelude::*;
pub mod engine;
pub mod filters;
pub mod types;

#[pymodule]
fn url_reputation_rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let _ = pyo3_log::try_init();
    m.add_class::<engine::URLReputationPlugin>()?;
    Ok(())
}
