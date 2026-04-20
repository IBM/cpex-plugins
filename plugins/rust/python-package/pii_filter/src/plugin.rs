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

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::{PyDict, PyList, PyModule};

    fn install_framework_mocks(py: Python<'_>) -> PyResult<()> {
        let sys = PyModule::import(py, "sys")?;
        let path = sys.getattr("path")?.cast_into::<PyList>()?;
        path.insert(
            0,
            format!("{}/test_support", env!("CARGO_MANIFEST_DIR")),
        )?;

        let mcpgateway = PyModule::import(py, "mcpgateway_mock")?;
        let plugins = PyModule::import(py, "mcpgateway_mock.plugins")?;
        let framework = PyModule::import(py, "mcpgateway_mock.plugins.framework")?;
        let modules = sys.getattr("modules")?.cast_into::<PyDict>()?;
        modules.set_item("mcpgateway", &mcpgateway)?;
        modules.set_item("mcpgateway.plugins", &plugins)?;
        modules.set_item("mcpgateway.plugins.framework", &framework)?;
        Ok(())
    }

    fn make_config(py: Python<'_>) -> Bound<'_, PyDict> {
        let config = PyDict::new(py);
        config.set_item("detect_ssn", true).unwrap();
        config.set_item("detect_email", true).unwrap();
        config.set_item("block_on_detection", false).unwrap();
        config
    }

    fn new_core(config: &Bound<'_, PyDict>) -> PIIFilterPluginCore {
        PIIFilterPluginCore::new(&config.clone().into_any()).unwrap()
    }

    fn framework_object<const N: usize>(
        py: Python<'_>,
        class_name: &str,
        kwargs: [(&str, Py<PyAny>); N],
    ) -> Py<PyAny> {
        build_framework_object(py, class_name, kwargs).unwrap()
    }

    fn new_context(py: Python<'_>) -> Py<PyAny> {
        framework_object(py, "PluginContext", [])
    }

    fn configure_log_capture(py: Python<'_>) -> PyResult<Py<PyAny>> {
        let logging = PyModule::import(py, "logging")?;
        let io = PyModule::import(py, "io")?;
        let stream = io.getattr("StringIO")?.call0()?;
        let handler = logging.getattr("StreamHandler")?.call1((&stream,))?;
        let logger = logging.getattr("getLogger")?.call1((LOGGER_NAME,))?;
        let handlers = PyList::new(py, [handler.clone()])?;
        logger.setattr("handlers", handlers)?;
        logger.setattr("propagate", false)?;
        logger.setattr("level", logging.getattr("INFO")?)?;
        Ok(stream.unbind())
    }

    fn read_log_output(py: Python<'_>, stream: &Py<PyAny>) -> String {
        stream
            .bind(py)
            .call_method0("getvalue")
            .unwrap()
            .extract::<String>()
            .unwrap()
    }

    #[test]
    fn prompt_pre_fetch_leaves_logs_and_metadata_disabled_by_default() {
        Python::initialize();
        Python::attach(|py| {
            install_framework_mocks(py).unwrap();
            let config = make_config(py);
            let plugin = new_core(&config);
            let log_stream = configure_log_capture(py).unwrap();
            let args = PyDict::new(py);
            args.set_item("email", "alice@example.com").unwrap();
            let payload = framework_object(
                py,
                "PromptPrehookPayload",
                [
                    (
                        "prompt_id",
                        "prompt-1".into_pyobject(py).unwrap().into_any().unbind(),
                    ),
                    ("args", args.clone().into_any().unbind()),
                ],
            );
            let context = new_context(py);

            let result = plugin
                .prompt_pre_fetch(py, &payload.bind(py), &context.bind(py))
                .unwrap();

            let modified_payload = result.bind(py).getattr("modified_payload").unwrap();
            let args_any = modified_payload.getattr("args").unwrap();
            let args = args_any.cast::<PyDict>().unwrap();
            assert_eq!(
                args.get_item("email")
                    .unwrap()
                    .unwrap()
                    .extract::<String>()
                    .unwrap(),
                "[REDACTED]"
            );
            assert!(
                !context
                    .bind(py)
                    .getattr("metadata")
                    .unwrap()
                    .cast::<PyDict>()
                    .unwrap()
                    .contains("pii_detections")
                    .unwrap()
            );
            assert!(!read_log_output(py, &log_stream).contains("PII detected during"));
        });
    }

    #[test]
    fn prompt_pre_fetch_records_metadata_and_logs_when_enabled() {
        Python::initialize();
        Python::attach(|py| {
            install_framework_mocks(py).unwrap();
            let config = make_config(py);
            config.set_item("include_detection_details", true).unwrap();
            config.set_item("log_detections", true).unwrap();
            let plugin = new_core(&config);
            let log_stream = configure_log_capture(py).unwrap();
            let args = PyDict::new(py);
            args.set_item("primary_email", "alice@example.com").unwrap();
            args.set_item("secondary_email", "bob@example.com").unwrap();
            let payload = framework_object(
                py,
                "PromptPrehookPayload",
                [
                    (
                        "prompt_id",
                        "prompt-1".into_pyobject(py).unwrap().into_any().unbind(),
                    ),
                    ("args", args.clone().into_any().unbind()),
                ],
            );
            let context = new_context(py);

            plugin
                .prompt_pre_fetch(py, &payload.bind(py), &context.bind(py))
                .unwrap();

            let metadata_any = context.bind(py).getattr("metadata").unwrap();
            let metadata = metadata_any.cast::<PyDict>().unwrap();
            let pii_detections_any = metadata.get_item("pii_detections").unwrap().unwrap();
            let pii_detections = pii_detections_any.cast::<PyDict>().unwrap();
            let stage_any = pii_detections
                .get_item("prompt_pre_fetch")
                .unwrap()
                .unwrap();
            let stage = stage_any.cast::<PyDict>().unwrap();
            assert_eq!(
                stage
                    .get_item("total_count")
                    .unwrap()
                    .unwrap()
                    .extract::<usize>()
                    .unwrap(),
                2
            );
            let log_output = read_log_output(py, &log_stream);
            assert!(log_output.contains("PII detected during prompt_pre_fetch"));
            assert!(log_output.contains("action=masked"));
        });
    }

    #[test]
    fn prompt_pre_fetch_blocks_when_configured() {
        Python::initialize();
        Python::attach(|py| {
            install_framework_mocks(py).unwrap();
            let config = make_config(py);
            config.set_item("block_on_detection", true).unwrap();
            let plugin = new_core(&config);
            let args = PyDict::new(py);
            args.set_item("ssn", "123-45-6789").unwrap();
            let payload = framework_object(
                py,
                "PromptPrehookPayload",
                [
                    (
                        "prompt_id",
                        "prompt-1".into_pyobject(py).unwrap().into_any().unbind(),
                    ),
                    ("args", args.clone().into_any().unbind()),
                ],
            );
            let context = new_context(py);

            let result = plugin
                .prompt_pre_fetch(py, &payload.bind(py), &context.bind(py))
                .unwrap();

            assert!(
                !result
                    .bind(py)
                    .getattr("continue_processing")
                    .unwrap()
                    .extract::<bool>()
                    .unwrap()
            );
            assert_eq!(
                result
                    .bind(py)
                    .getattr("violation")
                    .unwrap()
                    .getattr("code")
                    .unwrap()
                    .extract::<String>()
                    .unwrap(),
                "PII_DETECTED"
            );
        });
    }

    #[test]
    fn prompt_pre_fetch_skips_masking_when_detector_disabled() {
        Python::initialize();
        Python::attach(|py| {
            install_framework_mocks(py).unwrap();
            let config = make_config(py);
            config.set_item("detect_email", false).unwrap();
            let plugin = new_core(&config);
            let args = PyDict::new(py);
            args.set_item("email", "alice@example.com").unwrap();
            let payload = framework_object(
                py,
                "PromptPrehookPayload",
                [
                    (
                        "prompt_id",
                        "prompt-1".into_pyobject(py).unwrap().into_any().unbind(),
                    ),
                    ("args", args.clone().into_any().unbind()),
                ],
            );
            let context = new_context(py);

            let result = plugin
                .prompt_pre_fetch(py, &payload.bind(py), &context.bind(py))
                .unwrap();

            assert!(
                result
                    .bind(py)
                    .getattr("modified_payload")
                    .unwrap()
                    .is_none()
            );
        });
    }

    #[test]
    fn prompt_post_fetch_masks_and_blocks_message_content() {
        Python::initialize();
        Python::attach(|py| {
            install_framework_mocks(py).unwrap();
            let config = make_config(py);
            config.set_item("include_detection_details", true).unwrap();
            let plugin = new_core(&config);
            let content = framework_object(
                py,
                "TextContent",
                [(
                    "text",
                    "Contact alice@example.com"
                        .into_pyobject(py)
                        .unwrap()
                        .into_any()
                        .unbind(),
                )],
            );
            let message = framework_object(
                py,
                "Message",
                [
                    (
                        "role",
                        "assistant".into_pyobject(py).unwrap().into_any().unbind(),
                    ),
                    ("content", content),
                ],
            );
            let messages = PyList::new(py, [message]).unwrap();
            let result_obj = framework_object(
                py,
                "PromptResult",
                [("messages", messages.into_any().unbind())],
            );
            let payload = framework_object(py, "PromptPosthookPayload", [("result", result_obj)]);
            let context = new_context(py);

            let result = plugin
                .prompt_post_fetch(py, &payload.bind(py), &context.bind(py))
                .unwrap();

            let text = result
                .bind(py)
                .getattr("modified_payload")
                .unwrap()
                .getattr("result")
                .unwrap()
                .getattr("messages")
                .unwrap()
                .cast::<PyList>()
                .unwrap()
                .get_item(0)
                .unwrap()
                .getattr("content")
                .unwrap()
                .getattr("text")
                .unwrap()
                .extract::<String>()
                .unwrap();
            assert!(!text.contains("alice@example.com"));

            let block_config = make_config(py);
            block_config.set_item("block_on_detection", true).unwrap();
            let blocking_plugin = new_core(&block_config);
            let blocking_content = framework_object(
                py,
                "TextContent",
                [(
                    "text",
                    "Contact alice@example.com"
                        .into_pyobject(py)
                        .unwrap()
                        .into_any()
                        .unbind(),
                )],
            );
            let blocking_message = framework_object(
                py,
                "Message",
                [
                    (
                        "role",
                        "assistant".into_pyobject(py).unwrap().into_any().unbind(),
                    ),
                    ("content", blocking_content),
                ],
            );
            let blocking_messages = PyList::new(py, [blocking_message]).unwrap();
            let blocking_result_obj = framework_object(
                py,
                "PromptResult",
                [("messages", blocking_messages.into_any().unbind())],
            );
            let blocking_payload = framework_object(
                py,
                "PromptPosthookPayload",
                [("result", blocking_result_obj)],
            );
            let block_context = new_context(py);
            let blocked = blocking_plugin
                .prompt_post_fetch(py, &blocking_payload.bind(py), &block_context.bind(py))
                .unwrap();
            assert!(
                !blocked
                    .bind(py)
                    .getattr("continue_processing")
                    .unwrap()
                    .extract::<bool>()
                    .unwrap()
            );
            assert_eq!(
                blocked
                    .bind(py)
                    .getattr("violation")
                    .unwrap()
                    .getattr("code")
                    .unwrap()
                    .extract::<String>()
                    .unwrap(),
                "PII_DETECTED_IN_PROMPT_RESULT"
            );
        });
    }

    #[test]
    fn tool_hooks_mask_block_and_record_stats() {
        Python::initialize();
        Python::attach(|py| {
            install_framework_mocks(py).unwrap();
            let config = make_config(py);
            let plugin = new_core(&config);
            let tool_args = PyDict::new(py);
            let nested_user = PyDict::new(py);
            nested_user.set_item("email", "alice@example.com").unwrap();
            tool_args.set_item("user", nested_user).unwrap();
            let pre_payload = framework_object(
                py,
                "ToolPreInvokePayload",
                [
                    (
                        "name",
                        "search".into_pyobject(py).unwrap().into_any().unbind(),
                    ),
                    ("args", tool_args.into_any().unbind()),
                ],
            );
            let pre_context = new_context(py);
            let pre_result = plugin
                .tool_pre_invoke(py, &pre_payload.bind(py), &pre_context.bind(py))
                .unwrap();
            let pre_payload = pre_result.bind(py).getattr("modified_payload").unwrap();
            let pre_args_any = pre_payload.getattr("args").unwrap();
            let pre_args = pre_args_any.cast::<PyDict>().unwrap();
            let user_any = pre_args.get_item("user").unwrap().unwrap();
            let user = user_any.cast::<PyDict>().unwrap();
            assert_eq!(
                user.get_item("email")
                    .unwrap()
                    .unwrap()
                    .extract::<String>()
                    .unwrap(),
                "[REDACTED]"
            );

            let result_dict = PyDict::new(py);
            result_dict
                .set_item("contact", "alice@example.com")
                .unwrap();
            let post_payload = framework_object(
                py,
                "ToolPostInvokePayload",
                [
                    (
                        "name",
                        "search".into_pyobject(py).unwrap().into_any().unbind(),
                    ),
                    ("result", result_dict.clone().into_any().unbind()),
                ],
            );
            let post_context = new_context(py);
            let post_result = plugin
                .tool_post_invoke(py, &post_payload.bind(py), &post_context.bind(py))
                .unwrap();
            let modified_payload = post_result.bind(py).getattr("modified_payload").unwrap();
            let result_any = modified_payload.getattr("result").unwrap();
            let result_dict = result_any.cast::<PyDict>().unwrap();
            assert_eq!(
                result_dict
                    .get_item("contact")
                    .unwrap()
                    .unwrap()
                    .extract::<String>()
                    .unwrap(),
                "[REDACTED]"
            );
            let post_metadata = post_context.bind(py).getattr("metadata").unwrap();
            let stats_any = post_metadata
                .cast::<PyDict>()
                .unwrap()
                .get_item("pii_filter_stats")
                .unwrap()
                .unwrap();
            let stats = stats_any.cast::<PyDict>().unwrap();
            assert_eq!(
                stats
                    .get_item("total_detections")
                    .unwrap()
                    .unwrap()
                    .extract::<usize>()
                    .unwrap(),
                1
            );
            assert_eq!(
                stats
                    .get_item("total_masked")
                    .unwrap()
                    .unwrap()
                    .extract::<usize>()
                    .unwrap(),
                1
            );

            let blocking_config = make_config(py);
            blocking_config
                .set_item("block_on_detection", true)
                .unwrap();
            let blocking_plugin = new_core(&blocking_config);
            let blocked_result = PyDict::new(py);
            blocked_result
                .set_item("contact", "alice@example.com")
                .unwrap();
            let blocked_payload = framework_object(
                py,
                "ToolPostInvokePayload",
                [
                    (
                        "name",
                        "search".into_pyobject(py).unwrap().into_any().unbind(),
                    ),
                    ("result", blocked_result.into_any().unbind()),
                ],
            );
            let blocked_context = new_context(py);
            let blocked = blocking_plugin
                .tool_post_invoke(py, &blocked_payload.bind(py), &blocked_context.bind(py))
                .unwrap();
            assert!(
                !blocked
                    .bind(py)
                    .getattr("continue_processing")
                    .unwrap()
                    .extract::<bool>()
                    .unwrap()
            );
            assert!(
                blocked_context
                    .bind(py)
                    .getattr("metadata")
                    .unwrap()
                    .cast::<PyDict>()
                    .unwrap()
                    .get_item("pii_filter_stats")
                    .unwrap()
                    .is_none()
            );
        });
    }

    #[test]
    fn tool_post_invoke_hash_masking_is_salted_per_plugin_instance() {
        Python::initialize();
        Python::attach(|py| {
            install_framework_mocks(py).unwrap();
            let config = make_config(py);
            config.set_item("detect_email", false).unwrap();
            let custom_patterns = PyList::empty(py);
            let pattern = PyDict::new(py);
            pattern
                .set_item("pattern", r"Customer [A-Z]{3}\d{3}")
                .unwrap();
            pattern.set_item("description", "Customer code").unwrap();
            pattern.set_item("mask_strategy", "hash").unwrap();
            custom_patterns.append(pattern).unwrap();
            config.set_item("custom_patterns", custom_patterns).unwrap();

            let first = new_core(&config);
            let second = new_core(&config);
            let mk_payload = || {
                let result = PyDict::new(py);
                result.set_item("contact", "Customer ABC123").unwrap();
                framework_object(
                    py,
                    "ToolPostInvokePayload",
                    [
                        (
                            "name",
                            "search".into_pyobject(py).unwrap().into_any().unbind(),
                        ),
                        ("result", result.into_any().unbind()),
                    ],
                )
            };

            let first_result = first
                .tool_post_invoke(py, &mk_payload().bind(py), &new_context(py).bind(py))
                .unwrap();
            let second_result = second
                .tool_post_invoke(py, &mk_payload().bind(py), &new_context(py).bind(py))
                .unwrap();

            let first_result_any = first_result
                .bind(py)
                .getattr("modified_payload")
                .unwrap()
                .getattr("result")
                .unwrap();
            let first_result_dict = first_result_any.cast::<PyDict>().unwrap();
            let first_value = first_result_dict
                .get_item("contact")
                .unwrap()
                .unwrap()
                .extract::<String>()
                .unwrap();
            let second_result_any = second_result
                .bind(py)
                .getattr("modified_payload")
                .unwrap()
                .getattr("result")
                .unwrap();
            let second_result_dict = second_result_any.cast::<PyDict>().unwrap();
            let second_value = second_result_dict
                .get_item("contact")
                .unwrap()
                .unwrap()
                .extract::<String>()
                .unwrap();

            assert!(first_value.starts_with("[HASH:"));
            assert!(second_value.starts_with("[HASH:"));
            assert_ne!(first_value, second_value);
        });
    }

    #[test]
    fn tool_pre_invoke_propagates_nested_depth_errors() {
        Python::initialize();
        Python::attach(|py| {
            install_framework_mocks(py).unwrap();
            let config = make_config(py);
            config.set_item("max_nested_depth", 1).unwrap();
            let plugin = new_core(&config);
            let level2 = PyDict::new(py);
            level2.set_item("email", "alice@example.com").unwrap();
            let level1 = PyDict::new(py);
            level1.set_item("level2", level2).unwrap();
            let args = PyDict::new(py);
            args.set_item("level1", level1).unwrap();
            let payload = framework_object(
                py,
                "ToolPreInvokePayload",
                [
                    (
                        "name",
                        "search".into_pyobject(py).unwrap().into_any().unbind(),
                    ),
                    ("args", args.into_any().unbind()),
                ],
            );

            let err = plugin
                .tool_pre_invoke(py, &payload.bind(py), &new_context(py).bind(py))
                .unwrap_err();
            assert!(err.to_string().contains("maximum depth"));
        });
    }

    #[test]
    fn tool_post_invoke_stats_reset_per_request() {
        Python::initialize();
        Python::attach(|py| {
            install_framework_mocks(py).unwrap();
            let base_config = make_config(py);
            let plugin = new_core(&base_config);

            let first_result = PyDict::new(py);
            first_result
                .set_item("contact", "alice@example.com")
                .unwrap();
            let first_payload = framework_object(
                py,
                "ToolPostInvokePayload",
                [
                    (
                        "name",
                        "search".into_pyobject(py).unwrap().into_any().unbind(),
                    ),
                    ("result", first_result.into_any().unbind()),
                ],
            );
            let first_context = new_context(py);
            plugin
                .tool_post_invoke(py, &first_payload.bind(py), &first_context.bind(py))
                .unwrap();

            let second_result = PyDict::new(py);
            second_result.set_item("ssn", "123-45-6789").unwrap();
            let second_payload = framework_object(
                py,
                "ToolPostInvokePayload",
                [
                    (
                        "name",
                        "search".into_pyobject(py).unwrap().into_any().unbind(),
                    ),
                    ("result", second_result.into_any().unbind()),
                ],
            );
            let second_context = new_context(py);
            plugin
                .tool_post_invoke(py, &second_payload.bind(py), &second_context.bind(py))
                .unwrap();

            for context in [&first_context, &second_context] {
                let metadata = context.bind(py).getattr("metadata").unwrap();
                let stats_any = metadata
                    .cast::<PyDict>()
                    .unwrap()
                    .get_item("pii_filter_stats")
                    .unwrap()
                    .unwrap();
                let stats = stats_any.cast::<PyDict>().unwrap();
                assert_eq!(
                    stats
                        .get_item("total_detections")
                        .unwrap()
                        .unwrap()
                        .extract::<usize>()
                        .unwrap(),
                    1
                );
                assert_eq!(
                    stats
                        .get_item("total_masked")
                        .unwrap()
                        .unwrap()
                        .extract::<usize>()
                        .unwrap(),
                    1
                );
            }
        });
    }

    #[test]
    fn invalid_whitelist_pattern_is_rejected_at_core_construction() {
        Python::initialize();
        Python::attach(|py| {
            install_framework_mocks(py).unwrap();
            let config = make_config(py);
            config
                .set_item("whitelist_patterns", PyList::new(py, ["("]).unwrap())
                .unwrap();

            let err = match PIIFilterPluginCore::new(&config.into_any()) {
                Ok(_) => panic!("expected invalid whitelist pattern to fail"),
                Err(err) => err,
            };
            assert!(err.to_string().contains("Pattern compilation failed"));
        });
    }

    #[test]
    fn sorted_detection_types_are_stable() {
        let detections = HashMap::from([
            (
                PIIType::Ssn,
                vec![Detection {
                    value: "123-45-6789".to_string(),
                    start: 0,
                    end: 11,
                    mask_strategy: crate::config::MaskingStrategy::Redact,
                }],
            ),
            (
                PIIType::Email,
                vec![Detection {
                    value: "alice@example.com".to_string(),
                    start: 12,
                    end: 29,
                    mask_strategy: crate::config::MaskingStrategy::Redact,
                }],
            ),
        ]);

        assert_eq!(sorted_detection_types(&detections), vec!["email", "ssn"]);
        assert_eq!(count_detections(&detections), 2);
    }
}
