// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
//
// Rust-owned output length guard plugin core.

use cpex_framework_bridge::{build_framework_object_dyn, default_result as bridge_default_result};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyModule};
#[cfg(feature = "stub-gen")]
use pyo3_stub_gen::derive::*;

use crate::config::{LimitMode, OutputLengthGuardConfig, Strategy};
use crate::guards::{estimate_tokens, evaluate_text_limits, is_numeric_string, truncate};
use crate::structured::{ProcessResult, generate_text_representation, process_structured_data};

/// Namespaced metadata key
const PLUGIN_KEY: &str = "output_length_guard";

// ─── Python-exposed plugin core ──────────────────────────────────────────────

#[cfg_attr(feature = "stub-gen", gen_stub_pyclass)]
#[pyclass]
pub struct OutputLengthGuardPluginCore {
    cfg: OutputLengthGuardConfig,
}

#[cfg_attr(feature = "stub-gen", gen_stub_pymethods)]
#[pymethods]
impl OutputLengthGuardPluginCore {
    #[new]
    pub fn new(config: &Bound<'_, PyAny>) -> PyResult<Self> {
        let cfg = OutputLengthGuardConfig::from_py_object(config)?;
        Ok(Self { cfg })
    }

    /// Only hook this plugin registers: tool_post_invoke.
    #[pyo3(signature = (payload, context, extensions=None))]
    pub fn tool_post_invoke(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        context: &Bound<'_, PyAny>,
        extensions: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        let _ = &context;
        let trace_id = read_trace_id(extensions);
        let name = payload
            .getattr("name")
            .and_then(|v| v.extract::<String>())
            .unwrap_or_default();

        let result_val = payload.getattr("result")?;

        // Case 0: MCP CallToolResult dict with 'content' key
        if let Ok(result_dict) = result_val.cast::<PyDict>() {
            if let Some(content_val) = result_dict.get_item("content")?
                && let Ok(content_list) = content_val.cast::<PyList>()
            {
                return self.handle_mcp_content_dict(
                    py,
                    payload,
                    result_dict,
                    content_list,
                    trace_id.as_deref(),
                    &name,
                );
            }
            // Case 2: Dict with optional 'text' field
            return self.handle_text_dict(py, payload, result_dict, trace_id.as_deref(), &name);
        }

        // Case 1: Plain string
        if let Ok(text) = result_val.extract::<String>() {
            return self.handle_plain_string(py, payload, &text, trace_id.as_deref(), &name);
        }

        // Case 3 & 4: List
        if let Ok(list) = result_val.cast::<PyList>()
            && !list.is_empty()
        {
            // Case 3: MCP content array [{type: "text", text: "..."}]
            if let Ok(first) = list.get_item(0)
                && let Ok(first_dict) = first.cast::<PyDict>()
                && first_dict.get_item("type").is_ok_and(|v| v.is_some())
            {
                return self.handle_mcp_list(py, payload, list, trace_id.as_deref(), &name);
            }
            // Case 4: List of strings
            if list.iter().all(|item| item.extract::<String>().is_ok()) {
                return self.handle_string_list(py, payload, list, trace_id.as_deref(), &name);
            }
        }

        // Unsupported result type
        let meta = PyDict::new(py);
        meta.set_item("skipped", true)?;
        meta.set_item("reason", "unsupported_type")?;
        default_result_with_meta(py, "ToolPostInvokeResult", meta)
    }
}

// ─── Private helpers ─────────────────────────────────────────────────────────

impl OutputLengthGuardPluginCore {
    fn handle_plain_string(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        text: &str,
        trace_id: Option<&str>,
        _name: &str,
    ) -> PyResult<Py<PyAny>> {
        match handle_text(py, text, &self.cfg)? {
            TextResult::Violation(v) => build_blocked_result(py, trace_id, v),
            TextResult::Modified(new_text) => {
                let new_result_obj = new_text.into_pyobject(py)?.into_any().unbind();
                let new_payload = clone_payload_with_attr(py, payload, "result", &new_result_obj)?;
                let meta = build_text_meta(py, text, &new_text_str(&new_result_obj, py), false)?;
                let mut kwargs: Vec<(&str, Py<PyAny>)> =
                    vec![("modified_payload", new_payload), ("metadata", meta)];
                push_metrics_kwargs(py, trace_id, &mut kwargs, text.len(), true, 1)?;
                build_result_dyn(py, "ToolPostInvokeResult", kwargs)
            }
            TextResult::Unchanged => {
                let meta = build_text_meta(py, text, text, true)?;
                let kwargs: Vec<(&str, Py<PyAny>)> = vec![("metadata", meta)];
                build_result_dyn(py, "ToolPostInvokeResult", kwargs)
            }
        }
    }

    fn handle_text_dict(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        result_dict: &Bound<'_, PyDict>,
        trace_id: Option<&str>,
        _name: &str,
    ) -> PyResult<Py<PyAny>> {
        let text_val = match result_dict.get_item("text")? {
            Some(v) => v,
            None => return default_result(py, "ToolPostInvokeResult"),
        };
        let Ok(text) = text_val.extract::<String>() else {
            return default_result(py, "ToolPostInvokeResult");
        };

        match handle_text(py, &text, &self.cfg)? {
            TextResult::Violation(v) => build_blocked_result(py, trace_id, v),
            TextResult::Modified(new_text) => {
                let new_dict = clone_dict_with_key(py, result_dict, "text", &new_text)?;
                let new_payload = clone_payload_with_attr(py, payload, "result", &new_dict)?;
                let meta = build_text_meta(py, &text, &new_text, false)?;
                let mut kwargs: Vec<(&str, Py<PyAny>)> =
                    vec![("modified_payload", new_payload), ("metadata", meta)];
                push_metrics_kwargs(py, trace_id, &mut kwargs, text.len(), true, 1)?;
                build_result_dyn(py, "ToolPostInvokeResult", kwargs)
            }
            TextResult::Unchanged => {
                let meta = build_text_meta(py, &text, &text, true)?;
                let kwargs: Vec<(&str, Py<PyAny>)> = vec![("metadata", meta)];
                build_result_dyn(py, "ToolPostInvokeResult", kwargs)
            }
        }
    }

    fn handle_mcp_list(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        list: &Bound<'_, PyList>,
        trace_id: Option<&str>,
        _name: &str,
    ) -> PyResult<Py<PyAny>> {
        let mut total_chars: usize = 0;
        let mut items_modified: usize = 0;

        let (out_items, was_modified) = match self.process_mcp_items_result(py, list, trace_id)? {
            Ok(r) => r,
            Err(violation) => return build_blocked_result(py, trace_id, violation),
        };

        if was_modified {
            // tally chars for metrics (approximate: sum lengths of truncated items)
            for item in &out_items {
                if let Ok(s) = item.bind(py).extract::<String>() {
                    total_chars += s.len();
                    items_modified += 1;
                }
            }
            let new_list = PyList::new(py, out_items)?;
            let new_result_obj = new_list.into_any().unbind();
            let new_payload = clone_payload_with_attr(py, payload, "result", &new_result_obj)?;
            let meta = PyDict::new(py);
            meta.set_item("mcp_content_processed", true)?;
            let mut kwargs: Vec<(&str, Py<PyAny>)> = vec![
                ("modified_payload", new_payload),
                ("metadata", meta.into_any().unbind()),
            ];
            push_metrics_kwargs(py, trace_id, &mut kwargs, total_chars, true, items_modified)?;
            return build_result_dyn(py, "ToolPostInvokeResult", kwargs);
        }
        let meta = PyDict::new(py);
        meta.set_item("mcp_content_processed", true)?;
        let kwargs: Vec<(&str, Py<PyAny>)> = vec![("metadata", meta.into_any().unbind())];
        build_result_dyn(py, "ToolPostInvokeResult", kwargs)
    }

    fn handle_string_list(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        list: &Bound<'_, PyList>,
        trace_id: Option<&str>,
        _name: &str,
    ) -> PyResult<Py<PyAny>> {
        let mut modified = false;
        let mut total_chars_truncated: usize = 0;
        let mut items_modified: usize = 0;
        let mut out: Vec<String> = Vec::with_capacity(list.len());

        for item in list.iter() {
            let text: String = item.extract()?;
            match handle_text(py, &text, &self.cfg)? {
                TextResult::Violation(v) => return build_blocked_result(py, trace_id, v),
                TextResult::Modified(new_text) => {
                    total_chars_truncated += text.len();
                    items_modified += 1;
                    out.push(new_text);
                    modified = true;
                }
                TextResult::Unchanged => out.push(text),
            }
        }

        if modified {
            let new_list = PyList::new(py, &out)?;
            let new_result_obj = new_list.into_any().unbind();
            let new_payload = clone_payload_with_attr(py, payload, "result", &new_result_obj)?;
            let meta = PyDict::new(py);
            let mut kwargs: Vec<(&str, Py<PyAny>)> = vec![
                ("modified_payload", new_payload),
                ("metadata", meta.into_any().unbind()),
            ];
            push_metrics_kwargs(
                py,
                trace_id,
                &mut kwargs,
                total_chars_truncated,
                true,
                items_modified,
            )?;
            return build_result_dyn(py, "ToolPostInvokeResult", kwargs);
        }
        let meta = PyDict::new(py);
        let kwargs: Vec<(&str, Py<PyAny>)> = vec![("metadata", meta.into_any().unbind())];
        build_result_dyn(py, "ToolPostInvokeResult", kwargs)
    }

    fn handle_mcp_content_dict(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        result_dict: &Bound<'_, PyDict>,
        content_list: &Bound<'_, PyList>,
        trace_id: Option<&str>,
        _name: &str,
    ) -> PyResult<Py<PyAny>> {
        // PRIORITY: check structuredContent first
        let struct_key = find_struct_key(result_dict)?;

        let mut struct_modified = false;
        let mut new_result_dict_data: Option<Py<PyAny>> = None;

        if let Some(sk) = &struct_key {
            let struct_val = result_dict.get_item(sk.as_str())?.unwrap();
            match process_structured_data(py, &struct_val, &self.cfg, "", 0)? {
                ProcessResult::Violation {
                    reason,
                    description,
                    code,
                    details,
                } => {
                    let violation = build_violation(py, &reason, &description, &code, &details)?;
                    return build_blocked_result(py, trace_id, violation);
                }
                ProcessResult::Ok { value, modified } => {
                    if modified {
                        struct_modified = true;
                        // Rebuild content from structured data
                        let new_text = generate_text_representation(value.bind(py), 0)?;
                        let content_item = PyDict::new(py);
                        content_item.set_item("type", "text")?;
                        content_item.set_item("text", &new_text)?;
                        let new_content = PyList::new(py, [content_item])?;
                        let value_ref = value.clone_ref(py);
                        let built = copy_dict_replace_keys(
                            py,
                            result_dict,
                            &[
                                (sk.as_str(), value_ref),
                                ("content", new_content.into_any().unbind()),
                            ],
                        )?;
                        new_result_dict_data = Some(built);
                    }
                }
            }
        }

        if struct_modified {
            let nd = new_result_dict_data.unwrap();
            let new_payload = clone_payload_with_attr(py, payload, "result", &nd)?;
            let meta = PyDict::new(py);
            meta.set_item("mcp_result_processed", true)?;
            meta.set_item("items_modified", true)?;
            meta.set_item("structured_content_processed", true)?;
            let kwargs: Vec<(&str, Py<PyAny>)> = vec![
                ("modified_payload", new_payload),
                ("metadata", meta.into_any().unbind()),
            ];
            return build_result_dyn(py, "ToolPostInvokeResult", kwargs);
        }

        // Process content array
        let (out_items, was_modified) =
            match self.process_mcp_items_result(py, content_list, trace_id)? {
                Ok(r) => r,
                Err(violation) => return build_blocked_result(py, trace_id, violation),
            };

        let sc_processed = struct_key.is_some();

        if was_modified {
            let new_content_list = PyList::new(py, out_items)?;
            let built = copy_dict_replace_keys(
                py,
                result_dict,
                &[("content", new_content_list.into_any().unbind())],
            )?;
            let new_payload = clone_payload_with_attr(py, payload, "result", &built)?;
            let meta = PyDict::new(py);
            meta.set_item("mcp_result_processed", true)?;
            meta.set_item("items_modified", true)?;
            meta.set_item("structured_content_processed", sc_processed)?;
            let kwargs: Vec<(&str, Py<PyAny>)> = vec![
                ("modified_payload", new_payload),
                ("metadata", meta.into_any().unbind()),
            ];
            return build_result_dyn(py, "ToolPostInvokeResult", kwargs);
        }

        let meta = PyDict::new(py);
        meta.set_item("mcp_result_processed", true)?;
        meta.set_item("items_modified", false)?;
        meta.set_item("structured_content_processed", sc_processed)?;
        let kwargs: Vec<(&str, Py<PyAny>)> = vec![("metadata", meta.into_any().unbind())];
        build_result_dyn(py, "ToolPostInvokeResult", kwargs)
    }

    /// Process MCP content items, returning either (out_items, modified) or a violation.
    #[allow(clippy::type_complexity)]
    fn process_mcp_items_result(
        &self,
        py: Python<'_>,
        list: &Bound<'_, PyList>,
        _trace_id: Option<&str>,
    ) -> PyResult<Result<(Vec<Py<PyAny>>, bool), Py<PyAny>>> {
        // Security: reject lists that exceed max_structure_size
        if list.len() > self.cfg.max_structure_size && self.cfg.strategy == Strategy::Block {
            let violation = build_violation(
                py,
                "Structure size exceeds security limit",
                &format!(
                    "Content list has {} items, exceeding limit of {}",
                    list.len(),
                    self.cfg.max_structure_size
                ),
                "STRUCTURE_SIZE_VIOLATION",
                &[
                    ("size".to_string(), serde_json::json!(list.len())),
                    (
                        "max_size".to_string(),
                        serde_json::json!(self.cfg.max_structure_size),
                    ),
                ],
            )?;
            return Ok(Err(violation));
        }

        let mut modified = false;
        let mut out: Vec<Py<PyAny>> = Vec::with_capacity(list.len());

        for item in list.iter() {
            let Ok(item_dict) = item.cast::<PyDict>() else {
                out.push(item.unbind());
                continue;
            };

            // text item
            if item_dict
                .get_item("type")?
                .and_then(|v| v.extract::<String>().ok())
                .as_deref()
                == Some("text")
                && let Some(text_val) = item_dict.get_item("text")?
                && let Ok(text) = text_val.extract::<String>()
            {
                match handle_text(py, &text, &self.cfg)? {
                    TextResult::Violation(v) => return Ok(Err(v)),
                    TextResult::Modified(new_text) => {
                        let new_item = copy_dict_replace_keys(
                            py,
                            item_dict,
                            &[("text", new_text.into_pyobject(py)?.into_any().unbind())],
                        )?;
                        out.push(new_item);
                        modified = true;
                        continue;
                    }
                    TextResult::Unchanged => {}
                }
            }

            // resource item
            if item_dict
                .get_item("type")?
                .and_then(|v| v.extract::<String>().ok())
                .as_deref()
                == Some("resource")
                && let Some(resource_val) = item_dict.get_item("resource")?
                && let Ok(resource_dict) = resource_val.cast::<PyDict>()
                && let Some(text_val) = resource_dict.get_item("text")?
                && let Ok(text) = text_val.extract::<String>()
            {
                match handle_text(py, &text, &self.cfg)? {
                    TextResult::Violation(v) => return Ok(Err(v)),
                    TextResult::Modified(new_text) => {
                        let new_resource = copy_dict_replace_keys(
                            py,
                            resource_dict,
                            &[("text", new_text.into_pyobject(py)?.into_any().unbind())],
                        )?;
                        let new_item =
                            copy_dict_replace_keys(py, item_dict, &[("resource", new_resource)])?;
                        out.push(new_item);
                        modified = true;
                        continue;
                    }
                    TextResult::Unchanged => {}
                }
            }

            out.push(item.unbind());
        }

        Ok(Ok((out, modified)))
    }
}

// ─── Text handling ────────────────────────────────────────────────────────────

enum TextResult {
    Unchanged,
    Modified(String),
    Violation(Py<PyAny>),
}

fn handle_text(py: Python<'_>, text: &str, cfg: &OutputLengthGuardConfig) -> PyResult<TextResult> {
    if is_numeric_string(text) {
        return Ok(TextResult::Unchanged);
    }

    let length = text.len();
    let token_count = estimate_tokens(text, cfg.chars_per_token);
    let (below_min, above_max) = evaluate_text_limits(length, token_count, cfg);

    if !below_min && !above_max {
        return Ok(TextResult::Unchanged);
    }

    if cfg.strategy == Strategy::Block {
        let (reason, description, code, details) =
            if above_max && cfg.limit_mode == LimitMode::Token {
                (
                    "Output estimated token count out of bounds".to_string(),
                    format!(
                        "Estimated token count {} exceeds max_tokens {}",
                        token_count,
                        cfg.max_tokens.unwrap_or(0)
                    ),
                    "OUTPUT_TOKEN_VIOLATION".to_string(),
                    vec![
                        ("token_count".to_string(), serde_json::json!(token_count)),
                        ("max_tokens".to_string(), serde_json::json!(cfg.max_tokens)),
                        (
                            "chars_per_token".to_string(),
                            serde_json::json!(cfg.chars_per_token),
                        ),
                        (
                            "strategy".to_string(),
                            serde_json::json!(cfg.strategy.as_str()),
                        ),
                    ],
                )
            } else if above_max {
                (
                    "Output length out of bounds".to_string(),
                    format!(
                        "Result length {} exceeds max_chars {}",
                        length,
                        cfg.max_chars.unwrap_or(0)
                    ),
                    "OUTPUT_LENGTH_VIOLATION".to_string(),
                    vec![
                        ("length".to_string(), serde_json::json!(length)),
                        ("max_chars".to_string(), serde_json::json!(cfg.max_chars)),
                        (
                            "strategy".to_string(),
                            serde_json::json!(cfg.strategy.as_str()),
                        ),
                    ],
                )
            } else {
                (
                    "Output length below minimum".to_string(),
                    format!(
                        "Result length {} (tokens {}) below minimum",
                        length, token_count
                    ),
                    "OUTPUT_LENGTH_VIOLATION".to_string(),
                    vec![
                        ("length".to_string(), serde_json::json!(length)),
                        ("min_chars".to_string(), serde_json::json!(cfg.min_chars)),
                        ("token_count".to_string(), serde_json::json!(token_count)),
                        ("min_tokens".to_string(), serde_json::json!(cfg.min_tokens)),
                        (
                            "strategy".to_string(),
                            serde_json::json!(cfg.strategy.as_str()),
                        ),
                    ],
                )
            };
        let violation = build_violation(py, &reason, &description, &code, &details)?;
        return Ok(TextResult::Violation(violation));
    }

    // Truncate mode: only apply when above_max
    if above_max {
        let new_text = truncate(text, cfg);
        if new_text != text {
            return Ok(TextResult::Modified(new_text));
        }
    }

    Ok(TextResult::Unchanged)
}

// ─── Metrics helpers ──────────────────────────────────────────────────────────

struct MetricsArgs<'a> {
    chars_seen: usize,
    truncated_count: usize,
    blocked: bool,
    mode: &'a str,
    strategy: &'a str,
    stage: &'a str,
}

/// Build namespaced metrics dict for result.metadata.
/// Only emitted when trace_id is present.
fn build_output_metrics<'py>(
    py: Python<'py>,
    trace_id: Option<&str>,
    args: MetricsArgs<'_>,
) -> PyResult<Option<Bound<'py, PyDict>>> {
    if trace_id.is_none() {
        return Ok(None);
    }
    let inner = PyDict::new(py);
    inner.set_item("chars_seen", args.chars_seen)?;
    inner.set_item("truncated_count", args.truncated_count)?;
    inner.set_item("blocked", args.blocked)?;
    inner.set_item("limit_mode", args.mode)?;
    inner.set_item("strategy", args.strategy)?;
    inner.set_item("stage", args.stage)?;
    let outer = PyDict::new(py);
    outer.set_item(PLUGIN_KEY, inner)?;
    Ok(Some(outer))
}

fn push_metrics_kwargs(
    py: Python<'_>,
    trace_id: Option<&str>,
    kwargs: &mut Vec<(&str, Py<PyAny>)>,
    chars_seen: usize,
    truncated: bool,
    items_modified: usize,
) -> PyResult<()> {
    let Some(tid) = trace_id else {
        return Ok(());
    };
    if let Some(md) = build_output_metrics(
        py,
        Some(tid),
        MetricsArgs {
            chars_seen,
            truncated_count: if truncated { items_modified } else { 0 },
            blocked: false,
            mode: "character",
            strategy: "truncate",
            stage: "tool_post_invoke",
        },
    )? {
        kwargs.push(("metadata", md.into_any().unbind()));
    }
    Ok(())
}

// ─── Framework helpers ────────────────────────────────────────────────────────

fn build_violation(
    py: Python<'_>,
    reason: &str,
    description: &str,
    code: &str,
    details: &[(String, serde_json::Value)],
) -> PyResult<Py<PyAny>> {
    let details_dict = PyDict::new(py);
    for (k, v) in details {
        let py_val: Py<PyAny> = json_to_py(py, v)?;
        details_dict.set_item(k, py_val.bind(py))?;
    }
    build_framework_object_dyn(
        py,
        "PluginViolation",
        vec![
            ("reason", reason.into_pyobject(py)?.into_any().unbind()),
            (
                "description",
                description.into_pyobject(py)?.into_any().unbind(),
            ),
            ("code", code.into_pyobject(py)?.into_any().unbind()),
            ("details", details_dict.into_any().unbind()),
        ],
    )
}

fn build_blocked_result(
    py: Python<'_>,
    trace_id: Option<&str>,
    violation: Py<PyAny>,
) -> PyResult<Py<PyAny>> {
    let mut kwargs: Vec<(&str, Py<PyAny>)> = vec![
        (
            "continue_processing",
            false.into_pyobject(py)?.to_owned().into_any().unbind(),
        ),
        ("violation", violation),
    ];
    if let Some(tid) = trace_id
        && let Ok(Some(md)) = build_output_metrics(
            py,
            Some(tid),
            MetricsArgs {
                chars_seen: 0,
                truncated_count: 0,
                blocked: true,
                mode: "character",
                strategy: "block",
                stage: "tool_post_invoke",
            },
        )
    {
        kwargs.push(("metadata", md.into_any().unbind()));
    }
    build_result_dyn(py, "ToolPostInvokeResult", kwargs)
}

fn build_result_dyn(
    py: Python<'_>,
    class_name: &str,
    kwargs: Vec<(&str, Py<PyAny>)>,
) -> PyResult<Py<PyAny>> {
    build_framework_object_dyn(py, class_name, kwargs)
}

fn default_result(py: Python<'_>, class_name: &str) -> PyResult<Py<PyAny>> {
    bridge_default_result(py, class_name)
}

fn default_result_with_meta(
    py: Python<'_>,
    class_name: &str,
    meta: Bound<'_, PyDict>,
) -> PyResult<Py<PyAny>> {
    build_framework_object_dyn(py, class_name, vec![("metadata", meta.into_any().unbind())])
}

// ─── Payload mutation helpers ─────────────────────────────────────────────────

fn clone_payload_with_attr(
    py: Python<'_>,
    payload: &Bound<'_, PyAny>,
    attr: &str,
    new_value: &Py<PyAny>,
) -> PyResult<Py<PyAny>> {
    let cloned = if payload.hasattr("model_copy")? {
        let kwargs = PyDict::new(py);
        let update = PyDict::new(py);
        update.set_item(attr, new_value.bind(py))?;
        kwargs.set_item("update", update)?;
        payload.call_method("model_copy", (), Some(&kwargs))?
    } else {
        let copy = PyModule::import(py, "copy")?;
        let cloned = copy.getattr("copy")?.call1((payload,))?;
        cloned.setattr(attr, new_value.bind(py))?;
        cloned
    };
    Ok(cloned.unbind())
}

/// Clone a dict with one key replaced.
fn clone_dict_with_key(
    py: Python<'_>,
    dict: &Bound<'_, PyDict>,
    key: &str,
    new_val: &str,
) -> PyResult<Py<PyAny>> {
    let out = PyDict::new(py);
    for (k, v) in dict.iter() {
        out.set_item(&k, &v)?;
    }
    out.set_item(key, new_val)?;
    Ok(out.into_any().unbind())
}

/// Copy a dict and replace the given key/value pairs.
fn copy_dict_replace_keys(
    py: Python<'_>,
    dict: &Bound<'_, PyDict>,
    replacements: &[(&str, Py<PyAny>)],
) -> PyResult<Py<PyAny>> {
    let out = PyDict::new(py);
    for (k, v) in dict.iter() {
        out.set_item(&k, &v)?;
    }
    for (key, val) in replacements {
        out.set_item(*key, val.bind(py))?;
    }
    Ok(out.into_any().unbind())
}

fn find_struct_key(result_dict: &Bound<'_, PyDict>) -> PyResult<Option<String>> {
    for key in ["structuredContent", "structured_content"] {
        if let Some(val) = result_dict.get_item(key)?
            && !val.is_none()
        {
            return Ok(Some(key.to_string()));
        }
    }
    Ok(None)
}

fn json_to_py(py: Python<'_>, v: &serde_json::Value) -> PyResult<Py<PyAny>> {
    match v {
        serde_json::Value::Null => Ok(py.None()),
        serde_json::Value::Bool(b) => Ok(b.into_pyobject(py)?.to_owned().into_any().unbind()),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_pyobject(py)?.into_any().unbind())
            } else if let Some(f) = n.as_f64() {
                Ok(f.into_pyobject(py)?.into_any().unbind())
            } else {
                Ok(n.to_string().into_pyobject(py)?.into_any().unbind())
            }
        }
        serde_json::Value::String(s) => Ok(s.into_pyobject(py)?.into_any().unbind()),
        serde_json::Value::Array(arr) => {
            let list = PyList::empty(py);
            for item in arr {
                list.append(json_to_py(py, item)?.bind(py))?;
            }
            Ok(list.into_any().unbind())
        }
        serde_json::Value::Object(map) => {
            let d = PyDict::new(py);
            for (k, v) in map {
                d.set_item(k, json_to_py(py, v)?.bind(py))?;
            }
            Ok(d.into_any().unbind())
        }
    }
}

fn new_text_str(obj: &Py<PyAny>, py: Python<'_>) -> String {
    obj.bind(py).extract::<String>().unwrap_or_default()
}

fn build_text_meta(
    py: Python<'_>,
    original: &str,
    new_text: &str,
    within_bounds: bool,
) -> PyResult<Py<PyAny>> {
    let meta = PyDict::new(py);
    meta.set_item("original_length", original.len())?;
    meta.set_item("within_bounds", within_bounds)?;
    if !within_bounds {
        meta.set_item("truncated", new_text != original)?;
        meta.set_item("new_length", new_text.len())?;
    }
    Ok(meta.into_any().unbind())
}

/// Extract trace_id from extensions.request.trace_id
fn read_trace_id(extensions: Option<&Bound<'_, PyAny>>) -> Option<String> {
    let ext = extensions?;
    let request = ext.getattr("request").ok()?;
    if request.is_none() {
        return None;
    }
    let trace = request.getattr("trace_id").ok()?;
    if trace.is_none() {
        return None;
    }
    let s: String = trace.extract().ok()?;
    if s.is_empty() { None } else { Some(s) }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::{PyDict, PyList, PyModule};

    fn install_framework_module(py: Python<'_>) -> PyResult<()> {
        let framework = PyModule::from_code(
            py,
            pyo3::ffi::c_str!(
                r#"
class ToolPostInvokeResult:
    def __init__(self, modified_payload=None, continue_processing=True, violation=None, metadata=None):
        self.modified_payload = modified_payload
        self.continue_processing = continue_processing
        self.violation = violation
        self.metadata = metadata

class PluginViolation:
    def __init__(self, reason, code, description=None, details=None, mcp_error_code=None, http_status_code=None):
        self.reason = reason
        self.code = code
        self.description = description
        self.details = details
        self.mcp_error_code = mcp_error_code
        self.http_status_code = http_status_code
"#
            ),
            pyo3::ffi::c_str!("framework.py"),
            pyo3::ffi::c_str!("cpex.framework"),
        )?;
        let cpex = PyModule::from_code(
            py,
            pyo3::ffi::c_str!(""),
            pyo3::ffi::c_str!("cpex.py"),
            pyo3::ffi::c_str!("cpex"),
        )?;
        cpex.setattr("framework", &framework)?;
        let modules = PyModule::import(py, "sys")?
            .getattr("modules")?
            .cast_into::<PyDict>()?;
        modules.set_item("cpex", cpex)?;
        modules.set_item("cpex.framework", framework)?;
        Ok(())
    }

    fn make_core(
        max_chars: Option<usize>,
        strategy: &str,
    ) -> PyResult<OutputLengthGuardPluginCore> {
        pyo3::Python::attach(|py| {
            let d = PyDict::new(py);
            match max_chars {
                Some(n) => d.set_item("max_chars", n)?,
                None => d.set_item("max_chars", py.None())?,
            }
            d.set_item("strategy", strategy)?;
            d.set_item("limit_mode", "character")?;
            OutputLengthGuardPluginCore::new(d.as_any())
        })
    }

    fn make_payload<'py>(
        py: Python<'py>,
        name: &str,
        result: Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let module = PyModule::from_code(
            py,
            pyo3::ffi::c_str!(
                r#"
class Payload:
    def __init__(self, name, result):
        self.name = name
        self.result = result
"#
            ),
            pyo3::ffi::c_str!("payload.py"),
            pyo3::ffi::c_str!("payload"),
        )?;
        module.getattr("Payload")?.call1((name, result))
    }

    #[test]
    fn truncates_long_plain_string() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let core = make_core(Some(10), "truncate").unwrap();
            let text = "A".repeat(100).into_pyobject(py).unwrap().into_any();
            let payload = make_payload(py, "tool1", text).unwrap();
            let ctx = PyDict::new(py);
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), None)
                .unwrap();
            let result = result.bind(py);
            let modified = result.getattr("modified_payload").unwrap();
            assert!(!modified.is_none());
            let new_result: String = modified.getattr("result").unwrap().extract().unwrap();
            assert!(new_result.chars().count() <= 10);
        });
    }

    #[test]
    fn blocks_long_plain_string_in_block_mode() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let core = make_core(Some(10), "block").unwrap();
            let text = "A".repeat(100).into_pyobject(py).unwrap().into_any();
            let payload = make_payload(py, "tool1", text).unwrap();
            let ctx = PyDict::new(py);
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), None)
                .unwrap();
            let result = result.bind(py);
            let cp: bool = result
                .getattr("continue_processing")
                .unwrap()
                .extract()
                .unwrap();
            assert!(!cp);
            assert!(!result.getattr("violation").unwrap().is_none());
        });
    }

    #[test]
    fn short_plain_string_passes_through_unchanged() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let core = make_core(Some(1000), "truncate").unwrap();
            let text = "hello".into_pyobject(py).unwrap().into_any();
            let payload = make_payload(py, "tool1", text).unwrap();
            let ctx = PyDict::new(py);
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), None)
                .unwrap();
            let result = result.bind(py);
            assert!(result.getattr("modified_payload").unwrap().is_none());
        });
    }

    #[test]
    fn dict_with_text_field_is_truncated() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let core = make_core(Some(5), "truncate").unwrap();
            let d = PyDict::new(py);
            d.set_item("text", "hello world foo").unwrap();
            let payload = make_payload(py, "t", d.as_any().clone()).unwrap();
            let ctx = PyDict::new(py);
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), None)
                .unwrap();
            let result = result.bind(py);
            let modified = result.getattr("modified_payload").unwrap();
            assert!(!modified.is_none());
        });
    }

    #[test]
    fn dict_without_text_field_passes_through() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let core = make_core(Some(5), "truncate").unwrap();
            let d = PyDict::new(py);
            d.set_item("other", "value").unwrap();
            let payload = make_payload(py, "t", d.as_any().clone()).unwrap();
            let ctx = PyDict::new(py);
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), None)
                .unwrap();
            let result = result.bind(py);
            assert!(result.getattr("modified_payload").unwrap().is_none());
        });
    }

    #[test]
    fn mcp_list_text_item_is_truncated() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let core = make_core(Some(5), "truncate").unwrap();
            let item = PyDict::new(py);
            item.set_item("type", "text").unwrap();
            item.set_item("text", "hello world foo").unwrap();
            let list = PyList::new(py, [item]).unwrap();
            let payload = make_payload(py, "t", list.as_any().clone()).unwrap();
            let ctx = PyDict::new(py);
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), None)
                .unwrap();
            let result = result.bind(py);
            let modified = result.getattr("modified_payload").unwrap();
            assert!(!modified.is_none());
        });
    }

    #[test]
    fn mcp_content_dict_with_text_item_is_truncated() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let core = make_core(Some(5), "truncate").unwrap();
            let item = PyDict::new(py);
            item.set_item("type", "text").unwrap();
            item.set_item("text", "hello world foo").unwrap();
            let content_list = PyList::new(py, [item]).unwrap();
            let result_dict = PyDict::new(py);
            result_dict.set_item("content", content_list).unwrap();
            let payload = make_payload(py, "t", result_dict.as_any().clone()).unwrap();
            let ctx = PyDict::new(py);
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), None)
                .unwrap();
            let result = result.bind(py);
            let modified = result.getattr("modified_payload").unwrap();
            assert!(!modified.is_none());
        });
    }

    #[test]
    fn string_list_is_truncated() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let core = make_core(Some(5), "truncate").unwrap();
            let list = PyList::new(py, ["hello world", "short"]).unwrap();
            let payload = make_payload(py, "t", list.as_any().clone()).unwrap();
            let ctx = PyDict::new(py);
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), None)
                .unwrap();
            let result = result.bind(py);
            let modified = result.getattr("modified_payload").unwrap();
            assert!(!modified.is_none());
        });
    }

    #[test]
    fn metrics_emitted_only_when_trace_id_present() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let md = build_output_metrics(
                py,
                Some("t1"),
                MetricsArgs {
                    chars_seen: 100,
                    truncated_count: 1,
                    blocked: false,
                    mode: "character",
                    strategy: "truncate",
                    stage: "tool_post_invoke",
                },
            )
            .unwrap();
            assert!(md.is_some());
            let outer_dict = md.unwrap();
            let inner = outer_dict.get_item(PLUGIN_KEY).unwrap().unwrap();
            // Verify "chars_seen" key is present and not None
            let inner_dict = inner.cast::<pyo3::types::PyDict>().unwrap();
            assert!(inner_dict.contains("chars_seen").unwrap());
            // No trace => None
            let md2 = build_output_metrics(
                py,
                None,
                MetricsArgs {
                    chars_seen: 100,
                    truncated_count: 1,
                    blocked: false,
                    mode: "character",
                    strategy: "truncate",
                    stage: "tool_post_invoke",
                },
            )
            .unwrap();
            assert!(md2.is_none());
        });
    }

    #[test]
    fn read_trace_id_returns_value_when_present() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let module = PyModule::from_code(
                py,
                pyo3::ffi::c_str!(
                    "class Req:\n    def __init__(self, t):\n        self.trace_id = t\n\
                     class Ext:\n    def __init__(self, t):\n        self.request = Req(t)\n"
                ),
                pyo3::ffi::c_str!("ext.py"),
                pyo3::ffi::c_str!("ext"),
            )
            .unwrap();
            let with_id = module.getattr("Ext").unwrap().call1(("abc123",)).unwrap();
            let without = module.getattr("Ext").unwrap().call1((py.None(),)).unwrap();
            assert_eq!(read_trace_id(Some(&with_id)), Some("abc123".to_string()));
            assert_eq!(read_trace_id(Some(&without)), None);
            assert_eq!(read_trace_id(None), None);
        });
    }

    #[test]
    fn no_raw_content_in_metrics() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let md = build_output_metrics(
                py,
                Some("t1"),
                MetricsArgs {
                    chars_seen: 42,
                    truncated_count: 1,
                    blocked: false,
                    mode: "character",
                    strategy: "truncate",
                    stage: "tool_post_invoke",
                },
            )
            .unwrap()
            .unwrap();
            let inner = md.get_item(PLUGIN_KEY).unwrap().unwrap();
            let dumped = format!("{:?}", inner.str().unwrap());
            // No actual text content should be in the metrics
            assert!(!dumped.contains("hello world"));
        });
    }

    #[test]
    fn numeric_string_passes_through_without_modification() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let core = make_core(Some(2), "block").unwrap();
            let text = "42".into_pyobject(py).unwrap().into_any();
            let payload = make_payload(py, "t", text).unwrap();
            let ctx = PyDict::new(py);
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), None)
                .unwrap();
            let result = result.bind(py);
            // Numeric strings should pass through unchanged (no violation)
            let cp: bool = result
                .getattr("continue_processing")
                .unwrap()
                .extract()
                .unwrap();
            assert!(cp);
        });
    }

    #[test]
    fn token_mode_truncates_by_estimated_tokens() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let d = PyDict::new(py);
            d.set_item("max_tokens", 2).unwrap(); // 2 tokens * 4 chars = 8 chars
            d.set_item("limit_mode", "token").unwrap();
            d.set_item("strategy", "truncate").unwrap();
            d.set_item("max_chars", py.None()).unwrap();
            let core = OutputLengthGuardPluginCore::new(d.as_any()).unwrap();
            let text = "abcdefghijklmnop".into_pyobject(py).unwrap().into_any(); // 16 chars = 4 tokens
            let payload = make_payload(py, "t", text).unwrap();
            let ctx = PyDict::new(py);
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), None)
                .unwrap();
            let result = result.bind(py);
            let modified = result.getattr("modified_payload").unwrap();
            assert!(!modified.is_none());
        });
    }
}
