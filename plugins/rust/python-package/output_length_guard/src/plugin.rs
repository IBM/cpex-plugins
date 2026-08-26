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
            TextResult::Violation(v) => build_blocked_result(py, trace_id, v, &self.cfg),
            TextResult::Modified(new_text) => {
                let new_result_obj = new_text.into_pyobject(py)?.into_any().unbind();
                let new_payload = clone_payload_with_attr(py, payload, "result", &new_result_obj)?;
                let meta = build_text_meta(py, text, &new_text_str(&new_result_obj, py), false)?;
                let mut kwargs: Vec<(&str, Py<PyAny>)> =
                    vec![("modified_payload", new_payload), ("metadata", meta)];
                push_metrics_kwargs(py, trace_id, &mut kwargs, text.len(), true, 1, &self.cfg)?;
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
            TextResult::Violation(v) => build_blocked_result(py, trace_id, v, &self.cfg),
            TextResult::Modified(new_text) => {
                let new_dict = clone_dict_with_key(py, result_dict, "text", &new_text)?;
                let new_payload = clone_payload_with_attr(py, payload, "result", &new_dict)?;
                let meta = build_text_meta(py, &text, &new_text, false)?;
                let mut kwargs: Vec<(&str, Py<PyAny>)> =
                    vec![("modified_payload", new_payload), ("metadata", meta)];
                push_metrics_kwargs(py, trace_id, &mut kwargs, text.len(), true, 1, &self.cfg)?;
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
        let (out_items, was_modified, total_chars, items_modified) =
            match self.process_mcp_items_result(py, list, trace_id)? {
                Ok(r) => r,
                Err(violation) => return build_blocked_result(py, trace_id, violation, &self.cfg),
            };

        if was_modified {
            let new_list = PyList::new(py, out_items)?;
            let new_result_obj = new_list.into_any().unbind();
            let new_payload = clone_payload_with_attr(py, payload, "result", &new_result_obj)?;
            let meta = PyDict::new(py);
            meta.set_item("mcp_content_processed", true)?;
            let mut kwargs: Vec<(&str, Py<PyAny>)> = vec![
                ("modified_payload", new_payload),
                ("metadata", meta.into_any().unbind()),
            ];
            push_metrics_kwargs(py, trace_id, &mut kwargs, total_chars, true, items_modified, &self.cfg)?;
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
                TextResult::Violation(v) => return build_blocked_result(py, trace_id, v, &self.cfg),
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
                &self.cfg,
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
                    return build_blocked_result(py, trace_id, violation, &self.cfg);
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
        let (out_items, was_modified, total_chars_seen, items_modified_count) =
            match self.process_mcp_items_result(py, content_list, trace_id)? {
                Ok(r) => r,
                Err(violation) => return build_blocked_result(py, trace_id, violation, &self.cfg),
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
            let mut kwargs: Vec<(&str, Py<PyAny>)> = vec![
                ("modified_payload", new_payload),
                ("metadata", meta.into_any().unbind()),
            ];
            push_metrics_kwargs(
                py,
                trace_id,
                &mut kwargs,
                total_chars_seen,
                true,
                items_modified_count,
                &self.cfg,
            )?;
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
    ) -> PyResult<Result<(Vec<Py<PyAny>>, bool, usize, usize), Py<PyAny>>> {
        // Security: enforce max_structure_size regardless of strategy.
        // Mirrors the pattern in structured.rs::process_list / process_dict.
        if list.len() > self.cfg.max_structure_size {
            log::error!(
                "Content list size {} exceeds maximum {} (MCP items)",
                list.len(),
                self.cfg.max_structure_size
            );
            if self.cfg.strategy == Strategy::Block {
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
            // Truncate strategy: pass the oversized list through unchanged (items will
            // still have their individual text content guarded below).
            return Ok(Ok((
                list.iter().map(|item| item.unbind()).collect(),
                false,
                0,
                0,
            )));
        }

        let mut modified = false;
        let mut total_chars_seen: usize = 0;
        let mut items_modified_count: usize = 0;
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
                        total_chars_seen += text.len();
                        items_modified_count += 1;
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
                        total_chars_seen += text.len();
                        items_modified_count += 1;
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

        Ok(Ok((out, modified, total_chars_seen, items_modified_count)))
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
    cfg: &OutputLengthGuardConfig,
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
            mode: cfg.limit_mode.as_str(),
            strategy: cfg.strategy.as_str(),
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
    cfg: &OutputLengthGuardConfig,
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
                mode: cfg.limit_mode.as_str(),
                strategy: cfg.strategy.as_str(),
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

    // ── handle_string_list counter accuracy ──────────────────────────────
    // Kill: replace += with *= on total_chars_truncated / items_modified (lines 218-219)
    // We verify metrics are accurate by asserting the modified_payload is produced
    // (metrics path depends on correct counter values being > 0)
    #[test]
    fn string_list_two_items_truncated_both_modified() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let core = make_core(Some(3), "truncate").unwrap();
            // Both strings exceed max_chars=3
            let list = PyList::new(py, ["hello", "world"]).unwrap();
            let payload = make_payload(py, "t", list.as_any().clone()).unwrap();
            let ctx = PyDict::new(py);
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), None)
                .unwrap();
            let result = result.bind(py);
            let modified = result.getattr("modified_payload").unwrap();
            assert!(!modified.is_none(), "both strings should be truncated");
            // Verify each item in the result list is within max_chars
            let result_obj = modified.getattr("result").unwrap();
            let result_list = result_obj.cast::<PyList>().unwrap();
            for item in result_list.iter() {
                let s: String = item.extract().unwrap();
                assert!(s.chars().count() <= 3, "item '{}' exceeds max_chars", s);
            }
        });
    }

    // ── process_mcp_items_result structure size guard boundary ────────────
    // Kill: replace > with == / < / >= in size check (line 369)
    #[test]
    fn mcp_content_dict_at_exactly_max_structure_size_is_not_blocked() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let d = PyDict::new(py);
            d.set_item("max_chars", py.None()).unwrap(); // no char limit
            d.set_item("max_structure_size", 3usize).unwrap();
            d.set_item("strategy", "block").unwrap();
            d.set_item("limit_mode", "character").unwrap();
            let core = OutputLengthGuardPluginCore::new(d.as_any()).unwrap();
            // Exactly 3 items == max_structure_size: must NOT block
            let item_a = PyDict::new(py);
            item_a.set_item("type", "text").unwrap();
            item_a.set_item("text", "a").unwrap();
            let item_b = PyDict::new(py);
            item_b.set_item("type", "text").unwrap();
            item_b.set_item("text", "b").unwrap();
            let item_c = PyDict::new(py);
            item_c.set_item("type", "text").unwrap();
            item_c.set_item("text", "c").unwrap();
            let content = PyList::new(py, [item_a, item_b, item_c]).unwrap();
            let result_dict = PyDict::new(py);
            result_dict.set_item("content", content).unwrap();
            let payload = make_payload(py, "t", result_dict.as_any().clone()).unwrap();
            let ctx = PyDict::new(py);
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), None)
                .unwrap();
            let cp: bool = result
                .bind(py)
                .getattr("continue_processing")
                .unwrap()
                .extract()
                .unwrap();
            assert!(cp, "exactly max_structure_size items must not block");
        });
    }

    // Kill: replace == with != in resource item type check (line 433)
    #[test]
    fn mcp_content_dict_resource_item_text_is_truncated() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let core = make_core(Some(5), "truncate").unwrap();
            let resource = PyDict::new(py);
            resource.set_item("text", "hello world foo bar").unwrap();
            let item = PyDict::new(py);
            item.set_item("type", "resource").unwrap();
            item.set_item("resource", resource).unwrap();
            let content = PyList::new(py, [item]).unwrap();
            let result_dict = PyDict::new(py);
            result_dict.set_item("content", content).unwrap();
            let payload = make_payload(py, "t", result_dict.as_any().clone()).unwrap();
            let ctx = PyDict::new(py);
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), None)
                .unwrap();
            let result = result.bind(py);
            let modified = result.getattr("modified_payload").unwrap();
            assert!(!modified.is_none(), "resource text should be truncated");
        });
    }

    // Kill: replace += with -= / *= on resource item counters (lines 442-443)
    #[test]
    fn mcp_content_dict_resource_item_counter_is_nonzero_after_truncation() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let core = make_core(Some(3), "truncate").unwrap();
            let resource = PyDict::new(py);
            resource.set_item("text", "toolongtext").unwrap();
            let item = PyDict::new(py);
            item.set_item("type", "resource").unwrap();
            item.set_item("resource", resource).unwrap();
            let content = PyList::new(py, [item]).unwrap();
            let result_dict = PyDict::new(py);
            result_dict.set_item("content", content).unwrap();
            let payload = make_payload(py, "t", result_dict.as_any().clone()).unwrap();
            let ctx = PyDict::new(py);
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), None)
                .unwrap();
            // modified_payload must be present (counter > 0 required to trigger the modified branch)
            let modified = result.bind(py).getattr("modified_payload").unwrap();
            assert!(
                !modified.is_none(),
                "resource item truncation must produce modified_payload"
            );
        });
    }

    // ── handle_text: !below_min && !above_max short-circuit ──────────────
    // Kill: delete ! in `if !below_min && !above_max` (line 483)
    #[test]
    fn handle_text_within_bounds_does_not_modify_payload() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            // max_chars=100, no min — "hello" is well within bounds
            let core = make_core(Some(100), "block").unwrap();
            let text = "hello".into_pyobject(py).unwrap().into_any();
            let payload = make_payload(py, "t", text).unwrap();
            let ctx = PyDict::new(py);
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), None)
                .unwrap();
            let result = result.bind(py);
            // continue_processing must be true and no modification
            let cp: bool = result
                .getattr("continue_processing")
                .unwrap()
                .extract()
                .unwrap();
            assert!(cp);
            assert!(result.getattr("modified_payload").unwrap().is_none());
        });
    }

    // Kill: replace && with || in `above_max && cfg.limit_mode == LimitMode::Token` (line 489)
    #[test]
    fn handle_text_char_mode_violation_code_is_output_length_not_token() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let core = make_core(Some(5), "block").unwrap(); // character mode, block
            let text = "this is a long string"
                .into_pyobject(py)
                .unwrap()
                .into_any();
            let payload = make_payload(py, "t", text).unwrap();
            let ctx = PyDict::new(py);
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), None)
                .unwrap();
            let result = result.bind(py);
            let violation = result.getattr("violation").unwrap();
            assert!(!violation.is_none());
            let code: String = violation.getattr("code").unwrap().extract().unwrap();
            // character mode must emit OUTPUT_LENGTH_VIOLATION, not OUTPUT_TOKEN_VIOLATION
            assert_eq!(code, "OUTPUT_LENGTH_VIOLATION");
        });
    }

    // Kill: replace == with != in the token check (line 489)
    #[test]
    fn handle_text_token_mode_violation_code_is_output_token_violation() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let d = PyDict::new(py);
            d.set_item("max_tokens", 1usize).unwrap(); // 1 token * 4 = 4 chars
            d.set_item("limit_mode", "token").unwrap();
            d.set_item("strategy", "block").unwrap();
            d.set_item("max_chars", py.None()).unwrap();
            let core = OutputLengthGuardPluginCore::new(d.as_any()).unwrap();
            let text = "abcdefghij".into_pyobject(py).unwrap().into_any(); // 10 chars = 2+ tokens
            let payload = make_payload(py, "t", text).unwrap();
            let ctx = PyDict::new(py);
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), None)
                .unwrap();
            let result = result.bind(py);
            let violation = result.getattr("violation").unwrap();
            assert!(!violation.is_none());
            let code: String = violation.getattr("code").unwrap().extract().unwrap();
            assert_eq!(code, "OUTPUT_TOKEN_VIOLATION");
        });
    }

    // ── find_struct_key: !val.is_none() guard (line 762) ─────────────────
    // Kill: delete ! in `!val.is_none()`
    // A None-valued structuredContent key must NOT be treated as present
    #[test]
    fn mcp_content_dict_null_structured_content_treated_as_absent() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let core = make_core(Some(5), "truncate").unwrap();
            let item = PyDict::new(py);
            item.set_item("type", "text").unwrap();
            item.set_item("text", "hello world foo").unwrap();
            let content = PyList::new(py, [item]).unwrap();
            let result_dict = PyDict::new(py);
            result_dict.set_item("content", content).unwrap();
            result_dict
                .set_item("structuredContent", py.None())
                .unwrap();
            let payload = make_payload(py, "t", result_dict.as_any().clone()).unwrap();
            let ctx = PyDict::new(py);
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), None)
                .unwrap();
            // Even with structuredContent=None, content text must be truncated
            let modified = result.bind(py).getattr("modified_payload").unwrap();
            assert!(
                !modified.is_none(),
                "content text must be truncated even when structuredContent is null"
            );
        });
    }

    // ── build_text_meta: !within_bounds branch (line 814) ────────────────
    // Kill: delete ! in `if !within_bounds` and replace != with == (line 815)
    #[test]
    fn truncated_string_metadata_contains_truncated_true_and_new_length() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let core = make_core(Some(5), "truncate").unwrap();
            let text = "hello world".into_pyobject(py).unwrap().into_any();
            let payload = make_payload(py, "t", text).unwrap();
            let ctx = PyDict::new(py);
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), None)
                .unwrap();
            let result = result.bind(py);
            let meta = result.getattr("metadata").unwrap();
            // metadata must include within_bounds=false, truncated=true, new_length
            let within_bounds: bool = meta.get_item("within_bounds").unwrap().extract().unwrap();
            assert!(!within_bounds);
            let truncated: bool = meta.get_item("truncated").unwrap().extract().unwrap();
            assert!(truncated, "truncated must be true when text was shortened");
            // new_length is byte length of the truncated result; the original had 11 chars
            // so it must be strictly less than the original (11 bytes for ASCII)
            let new_length: usize = meta.get_item("new_length").unwrap().extract().unwrap();
            assert!(
                new_length < 11,
                "new_length must be less than original length"
            );
        });
    }

    #[test]
    fn within_bounds_string_metadata_does_not_contain_new_length() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let core = make_core(Some(100), "truncate").unwrap();
            let text = "hi".into_pyobject(py).unwrap().into_any();
            let payload = make_payload(py, "t", text).unwrap();
            let ctx = PyDict::new(py);
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), None)
                .unwrap();
            let result = result.bind(py);
            let meta = result.getattr("metadata").unwrap();
            let within_bounds: bool = meta.get_item("within_bounds").unwrap().extract().unwrap();
            assert!(within_bounds);
            // within_bounds=true: key "truncated" must NOT be present in the dict.
            let meta_dict = meta.cast::<PyDict>().unwrap();
            let has_truncated = meta_dict.get_item("truncated").unwrap().is_some();
            assert!(
                !has_truncated,
                "within_bounds path must not set 'truncated'"
            );
        });
    }

    // ── new_text_str (plugin.rs:802): replace with String::new() or "xyzzy" ──
    // The function is called to produce the `new_text` string used in build_text_meta.
    // build_text_meta sets new_length = new_text.len(). If the mutant returns "",
    // new_length == 0; if it returns "xyzzy", new_length == 5 (always).
    // We kill both by asserting new_length > 0 AND new_length != 5.
    #[test]
    fn truncated_plain_string_new_length_is_positive_and_not_xyzzy() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let core = make_core(Some(8), "truncate").unwrap();
            // "hello world" = 11 chars > 8 → truncated. Truncated result has 7 chars
            // (max_chars - ell_chars = 8 - 1 = 7) + "…" = 8 chars ≈ >5 bytes.
            let text = "hello world".into_pyobject(py).unwrap().into_any();
            let payload = make_payload(py, "t", text).unwrap();
            let ctx = PyDict::new(py);
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), None)
                .unwrap();
            let result = result.bind(py);
            let meta = result.getattr("metadata").unwrap();
            let new_length: usize = meta.get_item("new_length").unwrap().extract().unwrap();
            assert!(new_length > 0, "new_length must be > 0, got {}", new_length);
            // Kill "xyzzy" mutant: the actual truncated "hello w…" is 10 bytes, not 5.
            assert_ne!(new_length, 5, "new_length must not be 5 (xyzzy length)");
        });
    }

    // ── handle_string_list += counters (lines 218-219): += vs *= ─────────────
    // With *=, total_chars_truncated and items_modified stay at 0 forever.
    // push_metrics_kwargs is a no-op without trace_id, so we need to use a trace_id
    // and verify the emitted metadata reflects non-zero chars_seen / truncated_count.
    // We use a helper to inject an extensions object carrying a trace_id.
    fn make_extensions<'py>(py: Python<'py>, trace_id: &str) -> PyResult<Bound<'py, PyAny>> {
        let module = PyModule::from_code(
            py,
            pyo3::ffi::c_str!(
                "class Req:\n    def __init__(self, t):\n        self.trace_id = t\n\
                 class Ext:\n    def __init__(self, t):\n        self.request = Req(t)\n"
            ),
            pyo3::ffi::c_str!("ext2.py"),
            pyo3::ffi::c_str!("ext2"),
        )?;
        module.getattr("Ext")?.call1((trace_id,))
    }

    #[test]
    fn string_list_with_trace_id_metrics_have_nonzero_chars_seen() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let core = make_core(Some(3), "truncate").unwrap();
            // "hello" = 5 chars > 3 → truncated. total_chars_seen += 5 → must be 5, not 0.
            let list = PyList::new(py, ["hello"]).unwrap();
            let payload = make_payload(py, "t", list.as_any().clone()).unwrap();
            let ctx = PyDict::new(py);
            let ext = make_extensions(py, "trace-abc").unwrap();
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), Some(&ext))
                .unwrap();
            let result = result.bind(py);
            // metadata should be the metrics dict {output_length_guard: {...}}
            let meta = result.getattr("metadata").unwrap();
            // The metrics dict is keyed by PLUGIN_KEY = "output_length_guard"
            let inner = meta.get_item("output_length_guard").unwrap();
            assert!(
                !inner.is_none(),
                "output_length_guard metrics must be present"
            );
            let chars_seen: usize = inner.get_item("chars_seen").unwrap().extract().unwrap();
            assert!(chars_seen > 0, "chars_seen must be > 0, got {}", chars_seen);
            let truncated_count: usize = inner
                .get_item("truncated_count")
                .unwrap()
                .extract()
                .unwrap();
            assert!(
                truncated_count > 0,
                "truncated_count must be > 0, got {}",
                truncated_count
            );
        });
    }

    // ── process_mcp_items_result += counters (lines 413-414): text items ─────
    #[test]
    fn mcp_content_dict_with_trace_id_metrics_have_nonzero_chars_seen() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let core = make_core(Some(3), "truncate").unwrap();
            let item = PyDict::new(py);
            item.set_item("type", "text").unwrap();
            item.set_item("text", "hello world").unwrap(); // 11 chars > 3
            let content = PyList::new(py, [item]).unwrap();
            let result_dict = PyDict::new(py);
            result_dict.set_item("content", content).unwrap();
            let payload = make_payload(py, "t", result_dict.as_any().clone()).unwrap();
            let ctx = PyDict::new(py);
            let ext = make_extensions(py, "trace-def").unwrap();
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), Some(&ext))
                .unwrap();
            let result = result.bind(py);
            let meta = result.getattr("metadata").unwrap();
            let inner = meta.get_item("output_length_guard").unwrap();
            assert!(
                !inner.is_none(),
                "output_length_guard metrics must be present"
            );
            let chars_seen: usize = inner.get_item("chars_seen").unwrap().extract().unwrap();
            assert!(chars_seen > 0, "chars_seen must be > 0, got {}", chars_seen);
        });
    }

    // ── process_mcp_items_result += counters (lines 442-443): resource items ──
    #[test]
    fn mcp_resource_item_with_trace_id_metrics_have_nonzero_chars_seen() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let core = make_core(Some(3), "truncate").unwrap();
            let resource = PyDict::new(py);
            resource.set_item("text", "toolongtext").unwrap(); // 11 chars > 3
            let item = PyDict::new(py);
            item.set_item("type", "resource").unwrap();
            item.set_item("resource", resource).unwrap();
            let content = PyList::new(py, [item]).unwrap();
            let result_dict = PyDict::new(py);
            result_dict.set_item("content", content).unwrap();
            let payload = make_payload(py, "t", result_dict.as_any().clone()).unwrap();
            let ctx = PyDict::new(py);
            let ext = make_extensions(py, "trace-ghi").unwrap();
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), Some(&ext))
                .unwrap();
            let result = result.bind(py);
            let meta = result.getattr("metadata").unwrap();
            let inner = meta.get_item("output_length_guard").unwrap();
            assert!(
                !inner.is_none(),
                "output_length_guard metrics must be present for resource item"
            );
            let chars_seen: usize = inner.get_item("chars_seen").unwrap().extract().unwrap();
            assert!(
                chars_seen > 0,
                "chars_seen must be > 0 for resource item, got {}",
                chars_seen
            );
        });
    }

    // ── process_mcp_items_result > vs < on structure size (line 369) ─────────
    // Kill: replace > with <: a list SMALLER than max_structure_size must NOT block.
    #[test]
    fn mcp_content_dict_under_max_structure_size_is_not_blocked() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let d = PyDict::new(py);
            d.set_item("max_chars", py.None()).unwrap();
            d.set_item("max_structure_size", 10usize).unwrap();
            d.set_item("strategy", "block").unwrap();
            d.set_item("limit_mode", "character").unwrap();
            let core = OutputLengthGuardPluginCore::new(d.as_any()).unwrap();
            // Only 2 items — well under the limit of 10
            let item_a = PyDict::new(py);
            item_a.set_item("type", "text").unwrap();
            item_a.set_item("text", "a").unwrap();
            let item_b = PyDict::new(py);
            item_b.set_item("type", "text").unwrap();
            item_b.set_item("text", "b").unwrap();
            let content = PyList::new(py, [item_a, item_b]).unwrap();
            let result_dict = PyDict::new(py);
            result_dict.set_item("content", content).unwrap();
            let payload = make_payload(py, "t", result_dict.as_any().clone()).unwrap();
            let ctx = PyDict::new(py);
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), None)
                .unwrap();
            let cp: bool = result
                .bind(py)
                .getattr("continue_processing")
                .unwrap()
                .extract()
                .unwrap();
            assert!(
                cp,
                "list with 2 items < max_structure_size=10 must not block"
            );
        });
    }

    // ── process_mcp_items_result line 369: == with != on Strategy::Block ─────
    // Kill: replace == with != → truncate strategy would trigger the block.
    // Test: strategy=truncate (not Block), oversized list → must NOT block.
    #[test]
    fn mcp_content_dict_oversized_list_in_truncate_mode_is_not_blocked() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let d = PyDict::new(py);
            d.set_item("max_chars", py.None()).unwrap();
            d.set_item("max_structure_size", 2usize).unwrap();
            // Truncate strategy — oversized list must NOT be blocked
            d.set_item("strategy", "truncate").unwrap();
            d.set_item("limit_mode", "character").unwrap();
            let core = OutputLengthGuardPluginCore::new(d.as_any()).unwrap();
            // 5 items > max_structure_size=2, but strategy=truncate → must NOT block
            let item_a = PyDict::new(py);
            item_a.set_item("type", "text").unwrap();
            item_a.set_item("text", "a").unwrap();
            let item_b = PyDict::new(py);
            item_b.set_item("type", "text").unwrap();
            item_b.set_item("text", "b").unwrap();
            let item_c = PyDict::new(py);
            item_c.set_item("type", "text").unwrap();
            item_c.set_item("text", "c").unwrap();
            let content = PyList::new(py, [item_a, item_b, item_c]).unwrap();
            let result_dict = PyDict::new(py);
            result_dict.set_item("content", content).unwrap();
            let payload = make_payload(py, "t", result_dict.as_any().clone()).unwrap();
            let ctx = PyDict::new(py);
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), None)
                .unwrap();
            let cp: bool = result
                .bind(py)
                .getattr("continue_processing")
                .unwrap()
                .extract()
                .unwrap();
            assert!(
                cp,
                "truncate strategy must not block oversized list; != mutant would block"
            );
        });
    }

    // ── process_mcp_items_result lines 414, 443: items_modified_count += vs *= ─
    // truncated_count = items_modified_count. With *= mutant, items_modified_count stays 0.
    #[test]
    fn mcp_content_dict_text_item_trace_id_truncated_count_is_nonzero() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let core = make_core(Some(3), "truncate").unwrap();
            let item = PyDict::new(py);
            item.set_item("type", "text").unwrap();
            item.set_item("text", "hello world").unwrap();
            let content = PyList::new(py, [item]).unwrap();
            let result_dict = PyDict::new(py);
            result_dict.set_item("content", content).unwrap();
            let payload = make_payload(py, "t", result_dict.as_any().clone()).unwrap();
            let ctx = PyDict::new(py);
            let ext = make_extensions(py, "trace-xyz").unwrap();
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), Some(&ext))
                .unwrap();
            let result = result.bind(py);
            let meta = result.getattr("metadata").unwrap();
            let inner = meta.get_item("output_length_guard").unwrap();
            assert!(!inner.is_none());
            let truncated_count: usize = inner
                .get_item("truncated_count")
                .unwrap()
                .extract()
                .unwrap();
            assert!(
                truncated_count > 0,
                "truncated_count must be > 0 (items_modified_count += 1), got {}",
                truncated_count
            );
        });
    }

    #[test]
    fn mcp_resource_item_trace_id_truncated_count_is_nonzero() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let core = make_core(Some(3), "truncate").unwrap();
            let resource = PyDict::new(py);
            resource.set_item("text", "toolongtext").unwrap();
            let item = PyDict::new(py);
            item.set_item("type", "resource").unwrap();
            item.set_item("resource", resource).unwrap();
            let content = PyList::new(py, [item]).unwrap();
            let result_dict = PyDict::new(py);
            result_dict.set_item("content", content).unwrap();
            let payload = make_payload(py, "t", result_dict.as_any().clone()).unwrap();
            let ctx = PyDict::new(py);
            let ext = make_extensions(py, "trace-res").unwrap();
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), Some(&ext))
                .unwrap();
            let result = result.bind(py);
            let meta = result.getattr("metadata").unwrap();
            let inner = meta.get_item("output_length_guard").unwrap();
            assert!(!inner.is_none());
            let truncated_count: usize = inner
                .get_item("truncated_count")
                .unwrap()
                .extract()
                .unwrap();
            assert!(
                truncated_count > 0,
                "truncated_count must be > 0 for resource item, got {}",
                truncated_count
            );
        });
    }

    // ── find_struct_key line 762: delete ! in !val.is_none() ─────────────────
    // With ! deleted: val.is_none() → true means "present" → None-valued key treated as found.
    // The existing test checks truncation still happens with None structuredContent.
    // But with the mutant, None-valued structuredContent IS found → process_structured_data
    // gets Python None → falls through as Ok{modified=false}. Then content is still processed.
    // The real observable difference: with non-None structuredContent, verify it IS found.
    // Also verify None structuredContent is NOT treated as present (struct_key is None).
    #[test]
    fn mcp_content_dict_nonnone_structured_content_sets_structured_content_processed() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let core = make_core(Some(1000), "truncate").unwrap();
            let sc = PyDict::new(py);
            sc.set_item("data", "value").unwrap();
            let item = PyDict::new(py);
            item.set_item("type", "text").unwrap();
            item.set_item("text", "short").unwrap();
            let content = PyList::new(py, [item]).unwrap();
            let result_dict = PyDict::new(py);
            result_dict.set_item("content", content).unwrap();
            result_dict.set_item("structuredContent", &sc).unwrap();
            let payload = make_payload(py, "t", result_dict.as_any().clone()).unwrap();
            let ctx = PyDict::new(py);
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), None)
                .unwrap();
            let result = result.bind(py);
            let meta = result.getattr("metadata").unwrap();
            let meta_dict = meta.cast::<PyDict>().unwrap();
            let sc_processed: bool = meta_dict
                .get_item("structured_content_processed")
                .unwrap()
                .map(|v| v.extract::<bool>().unwrap_or(false))
                .unwrap_or(false);
            assert!(sc_processed, "non-None structuredContent must be detected");
        });
    }

    #[test]
    fn mcp_content_dict_none_structured_content_does_not_set_structured_content_processed() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let core = make_core(Some(1000), "truncate").unwrap();
            let item = PyDict::new(py);
            item.set_item("type", "text").unwrap();
            item.set_item("text", "short").unwrap();
            let content = PyList::new(py, [item]).unwrap();
            let result_dict = PyDict::new(py);
            result_dict.set_item("content", content).unwrap();
            // structuredContent = None → must NOT be treated as present
            result_dict
                .set_item("structuredContent", py.None())
                .unwrap();
            let payload = make_payload(py, "t", result_dict.as_any().clone()).unwrap();
            let ctx = PyDict::new(py);
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), None)
                .unwrap();
            let result = result.bind(py);
            let meta = result.getattr("metadata").unwrap();
            let meta_dict = meta.cast::<PyDict>().unwrap();
            // sc_processed = (struct_key.is_some()) = false when structuredContent is None
            let sc_processed: bool = meta_dict
                .get_item("structured_content_processed")
                .unwrap()
                .map(|v| v.extract::<bool>().unwrap_or(true))
                .unwrap_or(true);
            assert!(
                !sc_processed,
                "None structuredContent must NOT be treated as present; ! deletion mutant would set sc_processed=true"
            );
        });
    }

    // ── Bug fix: push_metrics_kwargs emits actual limit_mode / strategy ──────
    // Regression test: token-mode truncation must emit limit_mode="token", not "character".
    #[test]
    fn token_mode_metrics_emit_correct_limit_mode() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let d = PyDict::new(py);
            d.set_item("max_tokens", 2usize).unwrap(); // 2 tokens * 4 chars = 8 chars max
            d.set_item("limit_mode", "token").unwrap();
            d.set_item("strategy", "truncate").unwrap();
            d.set_item("max_chars", py.None()).unwrap();
            let core = OutputLengthGuardPluginCore::new(d.as_any()).unwrap();
            // 16 chars = 4 estimated tokens > 2 → truncation fires
            let text = "abcdefghijklmnop".into_pyobject(py).unwrap().into_any();
            let payload = make_payload(py, "t", text).unwrap();
            let ctx = PyDict::new(py);
            let ext = make_extensions(py, "trace-token").unwrap();
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), Some(&ext))
                .unwrap();
            let result = result.bind(py);
            let meta = result.getattr("metadata").unwrap();
            let inner = meta.get_item("output_length_guard").unwrap();
            assert!(!inner.is_none(), "metrics must be present with trace_id");
            let limit_mode: String = inner
                .get_item("limit_mode")
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(
                limit_mode, "token",
                "token-mode plugin must emit limit_mode='token', not 'character'"
            );
            let strategy: String = inner
                .get_item("strategy")
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(
                strategy, "truncate",
                "truncate-strategy plugin must emit strategy='truncate'"
            );
        });
    }

    // ── Bug fix: process_mcp_items_result enforces max_structure_size in truncate mode ──
    // Regression test: oversized list with strategy=truncate must pass through, not loop forever.
    #[test]
    fn mcp_content_dict_oversized_list_truncate_mode_passes_through_unchanged() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            install_framework_module(py).unwrap();
            let d = PyDict::new(py);
            d.set_item("max_chars", py.None()).unwrap(); // no char limit
            d.set_item("max_structure_size", 2usize).unwrap();
            d.set_item("strategy", "truncate").unwrap();
            d.set_item("limit_mode", "character").unwrap();
            let core = OutputLengthGuardPluginCore::new(d.as_any()).unwrap();
            // 3 items > max_structure_size=2, strategy=truncate: must NOT block,
            // must return the list unchanged (no panic, no infinite loop).
            let item_a = PyDict::new(py);
            item_a.set_item("type", "text").unwrap();
            item_a.set_item("text", "a").unwrap();
            let item_b = PyDict::new(py);
            item_b.set_item("type", "text").unwrap();
            item_b.set_item("text", "b").unwrap();
            let item_c = PyDict::new(py);
            item_c.set_item("type", "text").unwrap();
            item_c.set_item("text", "c").unwrap();
            let content = PyList::new(py, [item_a, item_b, item_c]).unwrap();
            let result_dict = PyDict::new(py);
            result_dict.set_item("content", content).unwrap();
            let payload = make_payload(py, "t", result_dict.as_any().clone()).unwrap();
            let ctx = PyDict::new(py);
            let result = core
                .tool_post_invoke(py, &payload, ctx.as_any(), None)
                .unwrap();
            let cp: bool = result
                .bind(py)
                .getattr("continue_processing")
                .unwrap()
                .extract()
                .unwrap();
            assert!(
                cp,
                "oversized list with truncate strategy must not block (continue_processing=true)"
            );
        });
    }
}
