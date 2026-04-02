// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
//
// Rust-owned PII filter plugin core. Python only keeps a tiny compatibility
// shim so the gateway can continue importing a `Plugin` subclass.

use std::collections::{BTreeSet, HashMap};

use cpex_framework_bridge::{build_framework_object, default_result as bridge_default_result};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyModule};
use pyo3_stub_gen::derive::*;

use crate::config::PIIType;
use crate::detector::{Detection, PIIDetectorRust};

const LOGGER_NAME: &str = "cpex_pii_filter.pii_filter";

#[gen_stub_pyclass]
#[pyclass]
pub struct PIIFilterPluginCore {
    detector: PIIDetectorRust,
}

#[gen_stub_pymethods]
#[pymethods]
impl PIIFilterPluginCore {
    #[new]
    pub fn new(config: &Bound<'_, PyAny>) -> PyResult<Self> {
        let detector = PIIDetectorRust::new(config)?;
        Ok(Self { detector })
    }

    pub fn prompt_pre_fetch(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        context: &Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        self.handle_nested_stage(
            py,
            payload,
            context,
            NestedStageSpec {
                source_attr: "args",
                stage: "prompt_pre_fetch",
                result_class: "PromptPrehookResult",
                subject_attr: "prompt_id",
                violation_reason: "PII detected in prompt arguments",
                violation_description: "Sensitive information detected in prompt arguments",
                violation_code: "PII_DETECTED",
                include_stats: false,
            },
        )
    }

    pub fn prompt_post_fetch(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        context: &Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        let result = payload.getattr("result")?;
        let messages_value = result.getattr("messages")?;
        let Ok(messages) = messages_value.cast::<PyList>() else {
            return default_result(py, "PromptPosthookResult");
        };

        let mut changed = false;
        let mut total_count = 0usize;
        let mut detected_types = BTreeSet::new();

        for message in messages.iter() {
            let Ok(content) = message.getattr("content") else {
                continue;
            };
            let Ok(text_obj) = content.getattr("text") else {
                continue;
            };
            let Ok(text) = text_obj.extract::<String>() else {
                continue;
            };

            let detections = self.detector.detect_rust(&text)?;
            if detections.is_empty() {
                continue;
            }

            total_count += count_detections(&detections);
            detected_types.extend(sorted_detection_types(&detections));
            let role = message.getattr("role")?.extract::<String>().ok();

            if self.detector.config.block_on_detection {
                self.log_detections(
                    py,
                    "prompt_post_fetch",
                    &detections,
                    "blocked",
                    role.as_deref(),
                    true,
                )?;
                return build_result(
                    py,
                    "PromptPosthookResult",
                    [
                        (
                            "continue_processing",
                            false.into_pyobject(py)?.to_owned().into_any().unbind(),
                        ),
                        (
                            "violation",
                            self.build_violation(
                                py,
                                "PII detected in prompt messages",
                                "Sensitive information detected in prompt result",
                                "PII_DETECTED_IN_PROMPT_RESULT",
                                &detections,
                            )?,
                        ),
                    ],
                );
            }

            let masked = self.detector.mask_rust(&text, &detections)?;
            content.setattr("text", masked)?;
            self.log_detections(
                py,
                "prompt_post_fetch",
                &detections,
                "masked",
                role.as_deref(),
                false,
            )?;
            changed = true;
        }

        self.record_metadata_summary(
            py,
            context,
            "prompt_post_fetch",
            total_count,
            detected_types.into_iter().collect(),
        )?;
        if changed {
            return build_result(
                py,
                "PromptPosthookResult",
                [("modified_payload", payload.clone().unbind())],
            );
        }

        default_result(py, "PromptPosthookResult")
    }

    pub fn tool_pre_invoke(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        context: &Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        self.handle_nested_stage(
            py,
            payload,
            context,
            NestedStageSpec {
                source_attr: "args",
                stage: "tool_pre_invoke",
                result_class: "ToolPreInvokeResult",
                subject_attr: "name",
                violation_reason: "PII detected in tool arguments",
                violation_description: "Sensitive information detected in tool arguments",
                violation_code: "PII_DETECTED_IN_TOOL_ARGS",
                include_stats: false,
            },
        )
    }

    pub fn tool_post_invoke(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        context: &Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        self.handle_nested_stage(
            py,
            payload,
            context,
            NestedStageSpec {
                source_attr: "result",
                stage: "tool_post_invoke",
                result_class: "ToolPostInvokeResult",
                subject_attr: "name",
                violation_reason: "PII detected in tool result",
                violation_description: "Sensitive information detected in tool result",
                violation_code: "PII_DETECTED_IN_TOOL_RESULT",
                include_stats: true,
            },
        )
    }
}

impl PIIFilterPluginCore {
    fn handle_nested_stage(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        context: &Bound<'_, PyAny>,
        spec: NestedStageSpec<'_>,
    ) -> PyResult<Py<PyAny>> {
        let source_value = payload.getattr(spec.source_attr)?;
        if source_value.is_none() {
            return default_result(py, spec.result_class);
        }

        let (modified, new_value, detections) =
            self.detector
                .process_nested_rust(py, &source_value, spec.source_attr)?;
        let subject = payload.getattr(spec.subject_attr)?.extract::<String>().ok();

        if !detections.is_empty() && self.detector.config.block_on_detection {
            self.log_detections(
                py,
                spec.stage,
                &detections,
                "blocked",
                subject.as_deref(),
                true,
            )?;
            return build_result(
                py,
                spec.result_class,
                [
                    (
                        "continue_processing",
                        false.into_pyobject(py)?.to_owned().into_any().unbind(),
                    ),
                    (
                        "violation",
                        self.build_violation(
                            py,
                            spec.violation_reason,
                            spec.violation_description,
                            spec.violation_code,
                            &detections,
                        )?,
                    ),
                ],
            );
        }

        self.record_metadata(py, context, spec.stage, &detections)?;
        if !detections.is_empty() {
            self.log_detections(
                py,
                spec.stage,
                &detections,
                "masked",
                subject.as_deref(),
                false,
            )?;
            if spec.include_stats {
                self.record_stats(py, context, &detections)?;
            }
        }
        if modified {
            payload.setattr(spec.source_attr, new_value.bind(py))?;
            return build_result(
                py,
                spec.result_class,
                [("modified_payload", payload.clone().unbind())],
            );
        }

        default_result(py, spec.result_class)
    }

    fn build_violation(
        &self,
        py: Python<'_>,
        reason: &str,
        description: &str,
        code: &str,
        detections: &HashMap<PIIType, Vec<Detection>>,
    ) -> PyResult<Py<PyAny>> {
        let details = PyDict::new(py);
        details.set_item("detected_types", sorted_detection_types(detections))?;
        details.set_item("count", count_detections(detections))?;

        build_framework_object(
            py,
            "PluginViolation",
            [
                ("reason", reason.into_pyobject(py)?.into_any().unbind()),
                (
                    "description",
                    description.into_pyobject(py)?.into_any().unbind(),
                ),
                ("code", code.into_pyobject(py)?.into_any().unbind()),
                ("details", details.into_any().unbind()),
            ],
        )
    }

    fn record_metadata(
        &self,
        py: Python<'_>,
        context: &Bound<'_, PyAny>,
        stage: &str,
        detections: &HashMap<PIIType, Vec<Detection>>,
    ) -> PyResult<()> {
        self.record_metadata_summary(
            py,
            context,
            stage,
            count_detections(detections),
            sorted_detection_types(detections),
        )
    }

    fn record_metadata_summary(
        &self,
        py: Python<'_>,
        context: &Bound<'_, PyAny>,
        stage: &str,
        total_count: usize,
        types: Vec<String>,
    ) -> PyResult<()> {
        if !self.detector.config.include_detection_details || total_count == 0 {
            return Ok(());
        }

        let metadata = context.getattr("metadata")?.cast_into::<PyDict>()?;
        let pii_detections = match metadata.get_item("pii_detections")? {
            Some(existing) => existing.cast_into::<PyDict>()?,
            None => {
                let value = PyDict::new(py);
                metadata.set_item("pii_detections", &value)?;
                value
            }
        };

        let stage_data = PyDict::new(py);
        stage_data.set_item("detected", true)?;
        stage_data.set_item("types", types)?;
        stage_data.set_item("total_count", total_count)?;
        pii_detections.set_item(stage, stage_data)?;
        Ok(())
    }

    fn record_stats(
        &self,
        py: Python<'_>,
        context: &Bound<'_, PyAny>,
        detections: &HashMap<PIIType, Vec<Detection>>,
    ) -> PyResult<()> {
        let metadata = context.getattr("metadata")?.cast_into::<PyDict>()?;
        let stats = PyDict::new(py);
        let total = count_detections(detections);
        stats.set_item("total_detections", total)?;
        stats.set_item("total_masked", total)?;
        metadata.set_item("pii_filter_stats", stats)?;
        Ok(())
    }

    fn log_detections(
        &self,
        py: Python<'_>,
        stage: &str,
        detections: &HashMap<PIIType, Vec<Detection>>,
        action: &str,
        subject: Option<&str>,
        blocked: bool,
    ) -> PyResult<()> {
        if !self.detector.config.log_detections || detections.is_empty() {
            return Ok(());
        }

        let logging = PyModule::import(py, "logging")?;
        let logger = logging.getattr("getLogger")?.call1((LOGGER_NAME,))?;
        let level = if blocked {
            logging.getattr("WARNING")?
        } else {
            logging.getattr("INFO")?
        };
        let mut message = format!(
            "PII detected during {}: action={} total={} types={}",
            stage,
            action,
            count_detections(detections),
            sorted_detection_types(detections).join(",")
        );
        if let Some(subject) = subject {
            message.push_str(&format!(" subject={}", subject));
        }
        logger.call_method1("log", (level, message))?;
        Ok(())
    }
}

struct NestedStageSpec<'a> {
    source_attr: &'a str,
    stage: &'a str,
    result_class: &'a str,
    subject_attr: &'a str,
    violation_reason: &'a str,
    violation_description: &'a str,
    violation_code: &'a str,
    include_stats: bool,
}

fn build_result<'py, const N: usize>(
    py: Python<'py>,
    class_name: &str,
    kwargs: [(&str, Py<PyAny>); N],
) -> PyResult<Py<PyAny>> {
    build_framework_object(py, class_name, kwargs)
}

fn default_result<'py>(py: Python<'py>, class_name: &str) -> PyResult<Py<PyAny>> {
    bridge_default_result(py, class_name)
}

fn count_detections(detections: &HashMap<PIIType, Vec<Detection>>) -> usize {
    detections.values().map(Vec::len).sum()
}

fn sorted_detection_types(detections: &HashMap<PIIType, Vec<Detection>>) -> Vec<String> {
    let mut kinds: Vec<String> = detections
        .keys()
        .map(|kind| kind.as_str().to_string())
        .collect();
    kinds.sort();
    kinds
}
