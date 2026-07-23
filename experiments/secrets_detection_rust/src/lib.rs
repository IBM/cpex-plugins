// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;

use config::SecretsDetectionConfig;
use cpex_core::factory::{PluginFactory, PluginInstance};
use cpex_core::hooks::TypedHandlerAdapter;
use cpex_core::registry::AnyHookHandler;
use cpex_sdk::{
    CmfHook, ContentPart, Extensions, HookHandler, MessagePayload, Plugin, PluginConfig,
    PluginContext, PluginError, PluginResult, PluginViolation,
};
use scanner::{scan_direct_text, scan_json_value, Finding};
use serde_json::{json, Map, Value};

pub mod config;
pub mod patterns;
pub mod scanner;

pub const KIND: &str = "validator/secrets-detection";
const VIOLATION_CODE: &str = "SECRETS_DETECTED";
const MAX_SECRET_TYPES: usize = 32;

#[derive(Debug)]
pub struct SecretsDetectionCore {
    config: PluginConfig,
    scanner_config: SecretsDetectionConfig,
}

impl SecretsDetectionCore {
    pub fn new(config: PluginConfig) -> Result<Self, config::ConfigError> {
        let scanner_config = SecretsDetectionConfig::from_value(config.config.as_ref())?;
        Ok(Self {
            config,
            scanner_config,
        })
    }

    fn scanner_config(&self) -> &SecretsDetectionConfig {
        &self.scanner_config
    }

    fn should_block(&self, count: usize) -> bool {
        self.scanner_config.block_on_detection && count >= self.scanner_config.min_findings_to_block
    }
}

impl Plugin for SecretsDetectionCore {
    fn config(&self) -> &PluginConfig {
        &self.config
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    PromptPreFetch,
    ToolPreInvoke,
    ToolPostInvoke,
    ResourcePostFetch,
}

pub struct StageHandler {
    core: Arc<SecretsDetectionCore>,
    stage: Stage,
}

impl StageHandler {
    fn new(core: Arc<SecretsDetectionCore>, stage: Stage) -> Self {
        Self { core, stage }
    }
}

impl Plugin for StageHandler {
    fn config(&self) -> &PluginConfig {
        self.core.config()
    }
}

impl HookHandler<CmfHook> for StageHandler {
    async fn handle(
        &self,
        payload: &MessagePayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let scan = self.scan_payload(payload);

        if self.core.should_block(scan.count) {
            let violation = build_violation(self.stage, scan.count, &scan.findings);
            let mut result = PluginResult::deny(violation);
            result.modified_payload = scan.modified_payload.or_else(|| Some(payload.clone()));
            attach_metrics(
                &mut result,
                extensions,
                scan.count,
                &scan.findings,
                DetectionOutcome::Blocked,
            );
            return result;
        }

        if let Some(modified_payload) = scan.modified_payload {
            let mut result = PluginResult::modify_payload(modified_payload);
            attach_metrics(
                &mut result,
                extensions,
                scan.count,
                &scan.findings,
                DetectionOutcome::Masked,
            );
            return result;
        }

        let mut result = PluginResult::allow();
        if scan.count > 0 {
            attach_metrics(
                &mut result,
                extensions,
                scan.count,
                &scan.findings,
                DetectionOutcome::None,
            );
        }
        result
    }
}

impl StageHandler {
    fn scan_payload(&self, payload: &MessagePayload) -> PayloadScan {
        let config = self.core.scanner_config();
        let mut modified_payload = payload.clone();
        let mut count = 0usize;
        let mut findings = Vec::new();
        let mut redacted_any = false;

        for part in &mut modified_payload.message.content {
            let Some(mut report) = self.scan_content_part(part, config) else {
                continue;
            };
            count += report.count;
            findings.append(&mut report.findings);
            if config.redact && report.redacted {
                redacted_any = true;
            }
        }

        PayloadScan {
            count,
            findings,
            modified_payload: if redacted_any {
                Some(modified_payload)
            } else {
                None
            },
        }
    }

    fn scan_content_part(
        &self,
        part: &mut ContentPart,
        config: &SecretsDetectionConfig,
    ) -> Option<PartScanReport> {
        match (self.stage, part) {
            (Stage::PromptPreFetch, ContentPart::PromptRequest { content }) => {
                let value = Value::Object(Map::from_iter(content.arguments.clone()));
                let report = scan_json_value(&value, config);
                let redacted = config.redact && report.count > 0;
                if redacted {
                    let Value::Object(arguments) = report.redacted else {
                        unreachable!("prompt arguments scan preserves JSON object shape");
                    };
                    content.arguments = arguments.into_iter().collect();
                }
                Some(PartScanReport {
                    count: report.count,
                    findings: report.findings,
                    redacted,
                })
            }
            (Stage::ToolPreInvoke, ContentPart::ToolCall { content }) => {
                let value = Value::Object(Map::from_iter(content.arguments.clone()));
                let report = scan_json_value(&value, config);
                let redacted = config.redact && report.count > 0;
                if redacted {
                    let Value::Object(arguments) = report.redacted else {
                        unreachable!("tool arguments scan preserves JSON object shape");
                    };
                    content.arguments = arguments.into_iter().collect();
                }
                Some(PartScanReport {
                    count: report.count,
                    findings: report.findings,
                    redacted,
                })
            }
            (Stage::ToolPostInvoke, ContentPart::ToolResult { content }) => {
                let report = scan_json_value(&content.content, config);
                let redacted = config.redact && report.count > 0;
                if redacted {
                    content.content = report.redacted;
                }
                Some(PartScanReport {
                    count: report.count,
                    findings: report.findings,
                    redacted,
                })
            }
            (Stage::ResourcePostFetch, ContentPart::Resource { content }) => {
                let text = content.content.as_ref()?;
                let report = scan_direct_text(text, config);
                let redacted = config.redact && report.count > 0;
                if redacted {
                    let Value::String(redacted_text) = report.redacted else {
                        unreachable!("direct text scan returns a string value");
                    };
                    content.content = Some(redacted_text);
                }
                Some(PartScanReport {
                    count: report.count,
                    findings: report.findings,
                    redacted,
                })
            }
            _ => None,
        }
    }
}

struct PayloadScan {
    count: usize,
    findings: Vec<Finding>,
    modified_payload: Option<MessagePayload>,
}

struct PartScanReport {
    count: usize,
    findings: Vec<Finding>,
    redacted: bool,
}

#[derive(Clone, Copy)]
enum DetectionOutcome {
    Masked,
    Blocked,
    None,
}

fn build_violation(stage: Stage, count: usize, findings: &[Finding]) -> PluginViolation {
    let details = HashMap::from([
        ("count".to_string(), json!(count)),
        ("examples".to_string(), sanitized_findings(findings)),
    ]);
    PluginViolation::new(VIOLATION_CODE, "Secrets detected")
        .with_description(stage.block_description())
        .with_details(details)
}

fn sanitized_findings(findings: &[Finding]) -> Value {
    Value::Array(
        findings
            .iter()
            .map(|finding| json!({ "type": finding.pii_type }))
            .collect(),
    )
}

fn attach_metrics(
    result: &mut PluginResult<MessagePayload>,
    extensions: &Extensions,
    count: usize,
    findings: &[Finding],
    outcome: DetectionOutcome,
) {
    let Some(metadata) = build_metrics(extensions, count, findings, outcome) else {
        return;
    };
    result.metadata = Some(metadata);
}

fn build_metrics(
    extensions: &Extensions,
    count: usize,
    findings: &[Finding],
    outcome: DetectionOutcome,
) -> Option<Value> {
    let trace_id = extensions
        .request
        .as_ref()
        .and_then(|request| request.trace_id.as_deref())?;
    if trace_id.is_empty() || count == 0 {
        return None;
    }

    let mut secret_types = findings
        .iter()
        .map(|finding| finding.pii_type.as_str())
        .collect::<Vec<_>>();
    secret_types.sort_unstable();
    secret_types.dedup();
    secret_types.truncate(MAX_SECRET_TYPES);

    let (masked, blocked) = match outcome {
        DetectionOutcome::Masked => (count, 0),
        DetectionOutcome::Blocked => (0, count),
        DetectionOutcome::None => (0, 0),
    };

    Some(json!({
        "secrets_detection": {
            "total_detections": count,
            "total_masked": masked,
            "total_blocked": blocked,
            "secret_types": secret_types,
        }
    }))
}

impl Stage {
    fn block_description(self) -> &'static str {
        match self {
            Stage::PromptPreFetch => "Potential secrets detected in prompt arguments",
            Stage::ToolPreInvoke => "Potential secrets detected in tool arguments",
            Stage::ToolPostInvoke => "Potential secrets detected in tool result",
            Stage::ResourcePostFetch => "Potential secrets detected in resource content",
        }
    }
}

pub struct SecretsDetectionFactory;

impl PluginFactory for SecretsDetectionFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let core = Arc::new(SecretsDetectionCore::new(config.clone()).map_err(|err| {
            PluginError::Config {
                message: err.to_string(),
            }
        })?);
        let handlers = config
            .hooks
            .iter()
            .filter_map(|hook| handler_for_hook(hook, Arc::clone(&core)))
            .collect();

        Ok(PluginInstance {
            plugin: core,
            handlers,
        })
    }
}

fn handler_for_hook(
    hook: &str,
    core: Arc<SecretsDetectionCore>,
) -> Option<(&'static str, Arc<dyn AnyHookHandler>)> {
    let stage = match hook {
        "cmf.prompt_pre_fetch" => Stage::PromptPreFetch,
        "cmf.tool_pre_invoke" => Stage::ToolPreInvoke,
        "cmf.tool_post_invoke" => Stage::ToolPostInvoke,
        "cmf.resource_post_fetch" => Stage::ResourcePostFetch,
        _ => return None,
    };
    let hook_name: &'static str = Box::leak(hook.to_owned().into_boxed_str());
    let handler = StageHandler::new(core, stage);
    let adapter: Arc<dyn AnyHookHandler> =
        Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(Arc::new(handler)));
    Some((hook_name, adapter))
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    use cpex::PluginManager;
    use cpex_core::executor::PipelineResult;
    use cpex_core::extensions::RequestExtension;
    use cpex_sdk::{
        ContentPart, Extensions, Message, OnError, PluginMode, PromptRequest, Resource,
        ResourceType, Role, ToolCall, ToolResult,
    };
    use serde_json::{json, Value};

    use super::*;

    #[tokio::test]
    async fn factory_registers_cmf_tool_pre_invoke_handler() {
        let payload = tool_call_payload(HashMap::from([("message".to_string(), json!("hello"))]));

        let result =
            invoke_manager("cmf.tool_pre_invoke", "", payload, Extensions::default()).await;

        assert!(result.continue_processing);
        assert!(result.violation.is_none());
    }

    #[tokio::test]
    async fn tool_post_invoke_redacts_json_content_through_manager() {
        let payload = tool_result_payload(json!({
            "message": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
        }));

        let result = invoke_manager(
            "cmf.tool_post_invoke",
            r#"      block_on_detection: false
      redact: true
      redaction_text: "[REDACTED]"
"#,
            payload,
            Extensions::default(),
        )
        .await;

        assert!(result.continue_processing);
        assert!(result.violation.is_none());
        assert_eq!(
            tool_result_content(pipeline_payload(&result))["message"],
            json!("AWS_ACCESS_KEY_ID=[REDACTED]")
        );
    }

    #[tokio::test]
    async fn prompt_pre_fetch_redacts_arguments_through_manager() {
        let payload = prompt_request_payload(HashMap::from([(
            "token".to_string(),
            json!("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
        )]));

        let result = invoke_manager(
            "cmf.prompt_pre_fetch",
            r#"      block_on_detection: false
      redact: true
      redaction_text: "[REDACTED]"
"#,
            payload,
            Extensions::default(),
        )
        .await;

        assert!(result.continue_processing);
        assert_eq!(
            prompt_argument(pipeline_payload(&result), "token"),
            &json!("AWS_ACCESS_KEY_ID=[REDACTED]")
        );
    }

    #[tokio::test]
    async fn resource_post_fetch_direct_text_ignores_field_filters_through_manager() {
        let payload = resource_payload("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE");

        let result = invoke_manager(
            "cmf.resource_post_fetch",
            r#"      block_on_detection: false
      redact: true
      redaction_text: "[REDACTED]"
      field_allowlist:
        - different.path
      field_denylist:
        - content.text
"#,
            payload,
            Extensions::default(),
        )
        .await;

        assert!(result.continue_processing);
        assert_eq!(
            resource_text(pipeline_payload(&result)),
            "AWS_ACCESS_KEY_ID=[REDACTED]"
        );
    }

    #[tokio::test]
    async fn tool_pre_invoke_threshold_counts_only_eligible_fields() {
        let payload = tool_call_payload(HashMap::from([
            (
                "allowed".to_string(),
                json!("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
            ),
            (
                "ignored".to_string(),
                json!("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
            ),
        ]));

        let result = invoke_manager(
            "cmf.tool_pre_invoke",
            r#"      block_on_detection: true
      min_findings_to_block: 2
      field_allowlist:
        - allowed
"#,
            payload,
            Extensions::default(),
        )
        .await;

        assert!(result.continue_processing);
        assert!(result.violation.is_none());
    }

    #[tokio::test]
    async fn direct_handler_returns_metadata_and_redacted_payload_on_block() {
        let payload = tool_call_payload(HashMap::from([(
            "message".to_string(),
            json!("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
        )]));

        let result = invoke_direct_handler(
            Stage::ToolPreInvoke,
            json!({
                "block_on_detection": true,
                "redact": true,
                "redaction_text": "[REDACTED]",
                "min_findings_to_block": 1
            }),
            payload,
            extensions_with_trace("trace-1"),
        )
        .await;

        let metadata = result.metadata.as_ref().unwrap();
        assert!(!result.continue_processing);
        assert_eq!(result.violation.as_ref().unwrap().code, VIOLATION_CODE);
        assert_eq!(metadata["secrets_detection"]["total_blocked"], json!(1));
        assert_eq!(
            tool_call_argument(result.modified_payload.as_ref().unwrap(), "message"),
            &json!("AWS_ACCESS_KEY_ID=[REDACTED]")
        );
        assert!(!metadata.to_string().contains("AKIAFAKE12345EXAMPLE"));
    }

    #[tokio::test]
    async fn direct_handler_omits_metadata_without_trace_id() {
        let payload = tool_call_payload(HashMap::from([(
            "message".to_string(),
            json!("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
        )]));

        let result = invoke_direct_handler(
            Stage::ToolPreInvoke,
            json!({
                "block_on_detection": false,
                "redact": true,
                "redaction_text": "[REDACTED]"
            }),
            payload,
            Extensions::default(),
        )
        .await;

        assert!(result.continue_processing);
        assert!(result.metadata.is_none());
        assert_eq!(
            tool_call_argument(result.modified_payload.as_ref().unwrap(), "message"),
            &json!("AWS_ACCESS_KEY_ID=[REDACTED]")
        );
    }

    #[tokio::test]
    async fn direct_handler_omits_metadata_for_clean_payload_with_trace_id() {
        let payload = tool_call_payload(HashMap::from([("message".to_string(), json!("hello"))]));

        let result = invoke_direct_handler(
            Stage::ToolPreInvoke,
            json!({
                "block_on_detection": false,
                "redact": true,
                "redaction_text": "[REDACTED]"
            }),
            payload,
            extensions_with_trace("trace-1"),
        )
        .await;

        assert!(result.continue_processing);
        assert!(result.violation.is_none());
        assert!(result.modified_payload.is_none());
        assert!(result.metadata.is_none());
    }

    #[tokio::test]
    async fn direct_handler_metadata_reports_masked_outcome() {
        let payload = tool_call_payload(HashMap::from([(
            "message".to_string(),
            json!("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
        )]));

        let result = invoke_direct_handler(
            Stage::ToolPreInvoke,
            json!({
                "block_on_detection": false,
                "redact": true,
                "redaction_text": "[REDACTED]"
            }),
            payload,
            extensions_with_trace("trace-1"),
        )
        .await;

        let metadata = result.metadata.as_ref().unwrap();
        assert!(result.continue_processing);
        assert_eq!(metadata["secrets_detection"]["total_detections"], json!(1));
        assert_eq!(metadata["secrets_detection"]["total_masked"], json!(1));
        assert_eq!(metadata["secrets_detection"]["total_blocked"], json!(0));
        assert_eq!(
            metadata["secrets_detection"]["secret_types"],
            json!(["aws_access_key_id"])
        );
        assert!(!metadata.to_string().contains("AKIAFAKE12345EXAMPLE"));
    }

    #[tokio::test]
    async fn direct_handler_metadata_reports_findings_only_outcome() {
        let payload = tool_call_payload(HashMap::from([(
            "message".to_string(),
            json!("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
        )]));

        let result = invoke_direct_handler(
            Stage::ToolPreInvoke,
            json!({
                "block_on_detection": false,
                "redact": false
            }),
            payload,
            extensions_with_trace("trace-1"),
        )
        .await;

        let metadata = result.metadata.as_ref().unwrap();
        assert!(result.continue_processing);
        assert!(result.violation.is_none());
        assert!(result.modified_payload.is_none());
        assert_eq!(metadata["secrets_detection"]["total_detections"], json!(1));
        assert_eq!(metadata["secrets_detection"]["total_masked"], json!(0));
        assert_eq!(metadata["secrets_detection"]["total_blocked"], json!(0));
        assert!(!metadata.to_string().contains("AKIAFAKE12345EXAMPLE"));
    }

    #[tokio::test]
    async fn direct_handler_metadata_omits_raw_secret_values() {
        let payload = tool_call_payload(HashMap::from([(
            "message".to_string(),
            json!("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
        )]));

        let result = invoke_direct_handler(
            Stage::ToolPreInvoke,
            json!({
                "block_on_detection": false,
                "redact": false
            }),
            payload,
            extensions_with_trace("trace-1"),
        )
        .await;

        let dumped = result.metadata.as_ref().unwrap().to_string();
        assert!(dumped.contains("aws_access_key_id"));
        assert!(!dumped.contains("AKIAFAKE12345EXAMPLE"));
        assert!(!dumped.contains("AWS_ACCESS_KEY_ID="));
    }

    async fn invoke_direct_handler(
        stage: Stage,
        config: Value,
        payload: MessagePayload,
        extensions: Extensions,
    ) -> PluginResult<MessagePayload> {
        let core = Arc::new(SecretsDetectionCore::new(plugin_config(config)).unwrap());
        let handler = StageHandler::new(core, stage);
        let mut ctx = PluginContext::new();
        handler.handle(&payload, &extensions, &mut ctx).await
    }

    #[tokio::test]
    async fn manager_drops_plugin_metadata_in_cpex_0_2_2() {
        let payload = tool_call_payload(HashMap::from([(
            "message".to_string(),
            json!("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
        )]));

        let result = invoke_manager(
            "cmf.tool_pre_invoke",
            r#"      block_on_detection: false
      redact: true
      redaction_text: "[REDACTED]"
"#,
            payload,
            extensions_with_trace("trace-1"),
        )
        .await;

        assert!(result.continue_processing);
        assert_eq!(
            tool_call_argument(pipeline_payload(&result), "message"),
            &json!("AWS_ACCESS_KEY_ID=[REDACTED]")
        );
        assert!(
            result.metadata.is_none(),
            "CPEX 0.2.2 erase_result does not carry PluginResult.metadata into PipelineResult"
        );
    }

    #[tokio::test]
    async fn manager_deny_drops_modified_payload_in_cpex_0_2_2() {
        let payload = tool_call_payload(HashMap::from([(
            "message".to_string(),
            json!("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
        )]));

        let result = invoke_manager(
            "cmf.tool_pre_invoke",
            r#"      block_on_detection: true
      redact: true
      redaction_text: "[REDACTED]"
      min_findings_to_block: 1
"#,
            payload,
            extensions_with_trace("trace-1"),
        )
        .await;

        assert!(!result.continue_processing);
        assert_eq!(result.violation.as_ref().unwrap().code, VIOLATION_CODE);
        assert!(
            result.modified_payload.is_none(),
            "CPEX 0.2.2 PipelineResult::denied does not surface denied modified_payload"
        );
        assert!(
            result.metadata.is_none(),
            "CPEX 0.2.2 erase_result does not carry PluginResult.metadata into PipelineResult"
        );
    }

    async fn invoke_manager(
        hook: &str,
        config_block: &str,
        payload: MessagePayload,
        extensions: Extensions,
    ) -> PipelineResult {
        let manager = Arc::new(PluginManager::default());
        manager.register_factory(KIND, Box::new(SecretsDetectionFactory));
        let yaml = plugin_yaml(hook, config_block);
        manager.load_config_yaml(&yaml).expect("config should load");
        manager.initialize().await.expect("initialize");

        let (result, background) = manager
            .invoke_named::<CmfHook>(hook, payload, extensions, None)
            .await;
        background.wait_for_background_tasks().await;
        result
    }

    fn plugin_yaml(hook: &str, config_block: &str) -> String {
        let config = if config_block.trim().is_empty() {
            "    config: {}\n".to_string()
        } else {
            format!("    config:\n{config_block}")
        };
        format!(
            r#"plugins:
  - name: secrets-detection
    kind: validator/secrets-detection
    hooks: ["{hook}"]
    mode: sequential
{config}"#
        )
    }

    fn plugin_config(config: Value) -> PluginConfig {
        PluginConfig {
            name: "secrets-detection".to_string(),
            kind: KIND.to_string(),
            description: None,
            author: None,
            version: None,
            hooks: vec!["cmf.tool_pre_invoke".to_string()],
            mode: PluginMode::Sequential,
            priority: 100,
            on_error: OnError::Fail,
            capabilities: HashSet::new(),
            tags: Vec::new(),
            conditions: Vec::new(),
            config: Some(config),
        }
    }

    fn extensions_with_trace(trace_id: &str) -> Extensions {
        Extensions {
            request: Some(Arc::new(RequestExtension {
                trace_id: Some(trace_id.to_string()),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    fn tool_call_payload(arguments: HashMap<String, Value>) -> MessagePayload {
        MessagePayload {
            message: Message::with_content(
                Role::User,
                vec![ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: "tool-call-1".into(),
                        name: "echo".into(),
                        arguments,
                        namespace: None,
                    },
                }],
            ),
        }
    }

    fn prompt_request_payload(arguments: HashMap<String, Value>) -> MessagePayload {
        MessagePayload {
            message: Message::with_content(
                Role::User,
                vec![ContentPart::PromptRequest {
                    content: PromptRequest {
                        prompt_request_id: "prompt-1".into(),
                        name: "summarize".into(),
                        arguments,
                        server_id: None,
                    },
                }],
            ),
        }
    }

    fn tool_result_payload(content: Value) -> MessagePayload {
        MessagePayload {
            message: Message::with_content(
                Role::Tool,
                vec![ContentPart::ToolResult {
                    content: ToolResult {
                        tool_call_id: "tool-call-1".into(),
                        tool_name: "echo".into(),
                        content,
                        is_error: false,
                    },
                }],
            ),
        }
    }

    fn resource_payload(text: &str) -> MessagePayload {
        MessagePayload {
            message: Message::with_content(
                Role::Tool,
                vec![ContentPart::Resource {
                    content: Resource {
                        resource_request_id: "resource-1".into(),
                        uri: "file:///tmp/secret.txt".into(),
                        resource_type: ResourceType::File,
                        content: Some(text.to_string()),
                        ..Default::default()
                    },
                }],
            ),
        }
    }

    fn pipeline_payload(result: &PipelineResult) -> &MessagePayload {
        result
            .modified_payload
            .as_ref()
            .expect("pipeline returns final payload on allow")
            .as_any()
            .downcast_ref::<MessagePayload>()
            .expect("CMF payload type")
    }

    fn tool_call_argument<'a>(payload: &'a MessagePayload, key: &str) -> &'a Value {
        let ContentPart::ToolCall { content } = &payload.message.content[0] else {
            panic!("expected tool call content");
        };
        content.arguments.get(key).expect("argument exists")
    }

    fn prompt_argument<'a>(payload: &'a MessagePayload, key: &str) -> &'a Value {
        let ContentPart::PromptRequest { content } = &payload.message.content[0] else {
            panic!("expected prompt request content");
        };
        content.arguments.get(key).expect("argument exists")
    }

    fn tool_result_content(payload: &MessagePayload) -> &Value {
        let ContentPart::ToolResult { content } = &payload.message.content[0] else {
            panic!("expected tool result content");
        };
        &content.content
    }

    fn resource_text(payload: &MessagePayload) -> &str {
        let ContentPart::Resource { content } = &payload.message.content[0] else {
            panic!("expected resource content");
        };
        content.content.as_deref().expect("text content exists")
    }
}
