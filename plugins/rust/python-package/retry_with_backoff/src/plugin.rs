// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use cpex_framework_bridge::build_framework_object;
use log::{debug, warn};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyList};
use pyo3_stub_gen::derive::*;
use rand::Rng;
use serde_json::Value;

use crate::config::RetryConfig;

const STATE_TTL_SECS: f64 = 300.0;

#[derive(Debug, Clone)]
pub struct ToolRetryState {
    pub consecutive_failures: u32,
    pub last_failure_at: f64,
}

impl ToolRetryState {
    fn new() -> Self {
        Self {
            consecutive_failures: 0,
            last_failure_at: 0.0,
        }
    }
}

static MONO_EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

fn monotonic_secs() -> f64 {
    let epoch = MONO_EPOCH.get_or_init(Instant::now);
    epoch.elapsed().as_secs_f64()
}

#[gen_stub_pyclass]
#[pyclass]
pub struct RetryWithBackoffPluginCore {
    config: RetryConfig,
    state_manager: Arc<Mutex<HashMap<String, ToolRetryState>>>,
}

#[gen_stub_pymethods]
#[pymethods]
impl RetryWithBackoffPluginCore {
    #[new]
    pub fn new(config: &Bound<'_, PyAny>) -> PyResult<Self> {
        let config_dict = if config.is_none() {
            PyDict::new(config.py())
        } else {
            config.cast::<PyDict>()?.clone()
        };

        let config = RetryConfig::from_py_dict(&config_dict)?;

        debug!(
            "RetryWithBackoffPluginCore initialized: max_retries={} base_ms={} max_ms={} jitter={}",
            config.max_retries, config.backoff_base_ms, config.max_backoff_ms, config.jitter
        );

        Ok(Self {
            config,
            state_manager: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn tool_post_invoke(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        context: &Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        // Extract tool name
        let tool_name = payload.getattr("name")?.extract::<String>()?;

        // Get tool-specific config
        let config = self.config.get_tool_config(&tool_name);

        // Extract request_id from context
        let global_context = context.getattr("global_context")?;
        let request_id = global_context.getattr("request_id")?.extract::<String>()?;

        // Extract result
        let result = payload.getattr("result")?;

        // Build metadata
        let metadata = self.build_metadata(py, &config)?;

        // Check if this is a failure
        let is_failure = self.is_failure(py, &result, &config)?;

        if !is_failure {
            // Success - clear state
            self.clear_state(&tool_name, &request_id);
            return build_framework_object(
                py,
                "ToolPostInvokeResult",
                [
                    (
                        "retry_delay_ms",
                        0u64.into_pyobject(py)?.into_any().unbind(),
                    ),
                    ("metadata", metadata),
                ],
            );
        }

        // Failure - update state and check retry budget
        let mut state_map = self.state_manager.lock().unwrap();
        self.evict_stale(&mut state_map);

        let key = format!("{}:{}", tool_name, request_id);
        let state = state_map.entry(key.clone()).or_insert_with(ToolRetryState::new);

        state.consecutive_failures += 1;
        state.last_failure_at = monotonic_secs();

        if state.consecutive_failures <= config.max_retries {
            // Within retry budget - calculate delay
            let attempt = state.consecutive_failures.saturating_sub(1);
            let delay_ms = compute_delay_ms(
                attempt,
                config.backoff_base_ms,
                config.max_backoff_ms,
                config.jitter,
            );

            debug!(
                "tool_post_invoke: tool={} request_id={} failure={}/{} delay_ms={}",
                tool_name, request_id, state.consecutive_failures, config.max_retries, delay_ms
            );

            return build_framework_object(
                py,
                "ToolPostInvokeResult",
                [
                    (
                        "retry_delay_ms",
                        delay_ms.into_pyobject(py)?.into_any().unbind(),
                    ),
                    ("metadata", metadata),
                ],
            );
        }

        // Exhausted retry budget - remove state
        warn!(
            "tool_post_invoke: tool={} request_id={} exhausted after {} failure(s)",
            tool_name, request_id, state.consecutive_failures
        );
        state_map.remove(&key);

        build_framework_object(
            py,
            "ToolPostInvokeResult",
            [
                (
                    "retry_delay_ms",
                    0u64.into_pyobject(py)?.into_any().unbind(),
                ),
                ("metadata", metadata),
            ],
        )
    }

    pub fn resource_post_fetch(
        &self,
        py: Python<'_>,
        _payload: &Bound<'_, PyAny>,
        _context: &Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        let metadata = self.build_metadata(py, &self.config)?;

        build_framework_object(py, "ResourcePostFetchResult", [("metadata", metadata)])
    }
}

impl RetryWithBackoffPluginCore {
    fn is_failure(
        &self,
        _py: Python<'_>,
        result: &Bound<'_, PyAny>,
        config: &RetryConfig,
    ) -> PyResult<bool> {
        // Check if result is a dict
        let Ok(result_dict) = result.cast::<PyDict>() else {
            return Ok(false);
        };

        let retry_status_set = config.retry_on_status_set();

        // Check isError flag
        if let Some(is_error) = result_dict.get_item("isError")? {
            if is_error.extract::<bool>().unwrap_or(false) {
                // Check structured content for status_code
                if let Some(structured) = result_dict.get_item("structuredContent")? {
                    if let Ok(structured_dict) = structured.cast::<PyDict>() {
                        if let Some(status) = structured_dict.get_item("status_code")? {
                            if let Ok(status_code) = status.extract::<i32>() {
                                return Ok(retry_status_set.contains(&status_code));
                            }
                        }
                    }
                }
                return Ok(true);
            }
        }

        // Check structuredContent
        if let Some(structured) = result_dict.get_item("structuredContent")? {
            if let Ok(structured_dict) = structured.cast::<PyDict>() {
                if let Some(is_error) = structured_dict.get_item("isError")? {
                    if is_error.extract::<bool>().unwrap_or(false) {
                        return Ok(true);
                    }
                }
                if let Some(status) = structured_dict.get_item("status_code")? {
                    if let Ok(status_code) = status.extract::<i32>() {
                        if retry_status_set.contains(&status_code) {
                            return Ok(true);
                        }
                    }
                }
            }
        }

        // Check text content if enabled
        if config.check_text_content {
            if let Some(content) = result_dict.get_item("content")? {
                if let Ok(content_list) = content.cast::<PyList>() {
                    for item in content_list.iter() {
                        if let Ok(item_dict) = item.cast::<PyDict>() {
                            // Check if type is "text"
                            if let Some(item_type) = item_dict.get_item("type")? {
                                if item_type.extract::<String>().ok() != Some("text".to_string()) {
                                    continue;
                                }
                            }
                            // Try to parse text as JSON
                            if let Some(text) = item_dict.get_item("text")? {
                                if let Ok(text_str) = text.extract::<String>() {
                                    if let Ok(parsed) = serde_json::from_str::<Value>(&text_str) {
                                        if let Some(obj) = parsed.as_object() {
                                            // Check isError in parsed JSON
                                            if obj.get("isError").and_then(|v| v.as_bool())
                                                == Some(true)
                                            {
                                                return Ok(true);
                                            }
                                            // Check status_code in parsed JSON
                                            if let Some(status) =
                                                obj.get("status_code").and_then(|v| v.as_i64())
                                            {
                                                if retry_status_set.contains(&(status as i32)) {
                                                    return Ok(true);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(false)
    }

    fn build_metadata(&self, py: Python<'_>, config: &RetryConfig) -> PyResult<Py<PyAny>> {
        let metadata = PyDict::new(py);
        let retry_policy = PyDict::new(py);

        retry_policy.set_item("max_retries", config.max_retries)?;
        retry_policy.set_item("backoff_base_ms", config.backoff_base_ms)?;
        retry_policy.set_item("max_backoff_ms", config.max_backoff_ms)?;
        retry_policy.set_item("retry_on_status", config.retry_on_status.clone())?;

        metadata.set_item("retry_policy", retry_policy)?;
        Ok(metadata.into_any().unbind())
    }

    fn clear_state(&self, tool: &str, request_id: &str) {
        let mut state_map = self.state_manager.lock().unwrap();
        let key = format!("{}:{}", tool, request_id);
        state_map.remove(&key);
    }

    fn evict_stale(&self, map: &mut HashMap<String, ToolRetryState>) {
        let cutoff = monotonic_secs() - STATE_TTL_SECS;
        map.retain(|_, value| value.last_failure_at <= 0.0 || value.last_failure_at >= cutoff);
    }
}

fn compute_delay_ms(attempt: u32, base_ms: u64, max_ms: u64, jitter: bool) -> u64 {
    let ceiling = base_ms
        .saturating_mul(2u64.saturating_pow(attempt))
        .min(max_ms);
    if jitter {
        rand::thread_rng().gen_range(0..=ceiling)
    } else {
        ceiling
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_delay_ms_no_jitter() {
        assert_eq!(compute_delay_ms(0, 100, 10_000, false), 100);
        assert_eq!(compute_delay_ms(1, 100, 10_000, false), 200);
        assert_eq!(compute_delay_ms(2, 100, 10_000, false), 400);
        assert_eq!(compute_delay_ms(3, 100, 10_000, false), 800);
    }

    #[test]
    fn test_compute_delay_ms_capped() {
        assert_eq!(compute_delay_ms(10, 100, 500, false), 500);
    }

    #[test]
    fn test_compute_delay_ms_no_overflow() {
        let d = compute_delay_ms(63, 100, 5_000, false);
        assert_eq!(d, 5_000);
    }

    #[test]
    fn test_compute_delay_ms_with_jitter() {
        let delay = compute_delay_ms(1, 100, 10_000, true);
        assert!(delay <= 200);
    }

    #[test]
    fn test_tool_retry_state_new() {
        let state = ToolRetryState::new();
        assert_eq!(state.consecutive_failures, 0);
        assert_eq!(state.last_failure_at, 0.0);
    }

    #[test]
    fn test_monotonic_secs_increases() {
        let t1 = monotonic_secs();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let t2 = monotonic_secs();
        assert!(t2 > t1);
    }
}
