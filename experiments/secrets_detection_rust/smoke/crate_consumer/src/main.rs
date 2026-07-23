// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;

use cpex::PluginManager;
use cpex_core::executor::PipelineResult;
use cpex_sdk::{
    CmfHook, ContentPart, Extensions, Message, MessagePayload, PromptRequest, Resource,
    ResourceType, Role, ToolCall, ToolResult,
};
use secrets_detection_rust::{SecretsDetectionFactory, KIND};
use serde_json::{json, Value};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    ensure_invalid_config_is_rejected().await;
    tool_redact_smoke().await;
    tool_block_smoke().await;
    prompt_filter_smoke().await;
    tool_allow_deny_smoke().await;
    tool_result_filter_smoke().await;
    resource_block_smoke().await;
    println!("crate-level smoke tests passed");
}

async fn ensure_invalid_config_is_rejected() {
    let result = load_manager(
        "cmf.tool_pre_invoke",
        r#"      field_allowlist:
        - bad.
"#,
    )
    .await;

    let err = match result {
        Ok(_) => panic!("invalid field_allowlist did not fail"),
        Err(err) => err,
    };
    assert!(
        err.contains("field_allowlist path \"bad.\" must not start or end with '.'"),
        "unexpected invalid config error: {err}"
    );
    println!("invalid config rejected: {err}");
}

async fn tool_redact_smoke() {
    let payload = tool_call_payload(HashMap::from([(
        "token".to_string(),
        json!("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
    )]));

    let result = invoke_manager(
        "cmf.tool_pre_invoke",
        r#"      block_on_detection: false
      redact: true
      redaction_text: "[REDACTED]"
"#,
        payload,
    )
    .await;

    assert!(result.continue_processing);
    assert!(result.violation.is_none());
    assert_eq!(
        tool_call_argument(pipeline_payload(&result), "token"),
        &json!("AWS_ACCESS_KEY_ID=[REDACTED]")
    );
    println!("tool-redact passed");
}

async fn tool_block_smoke() {
    let payload = tool_call_payload(HashMap::from([(
        "token".to_string(),
        json!("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
    )]));

    let result = invoke_manager(
        "cmf.tool_pre_invoke",
        r#"      block_on_detection: true
      redact: false
      min_findings_to_block: 1
"#,
        payload,
    )
    .await;

    assert!(!result.continue_processing);
    assert_eq!(result.violation.as_ref().unwrap().code, "SECRETS_DETECTED");
    assert!(result.modified_payload.is_none());
    println!("tool-block passed");
}

async fn prompt_filter_smoke() {
    let payload = prompt_request_payload(HashMap::from([
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
        "cmf.prompt_pre_fetch",
        r#"      block_on_detection: false
      redact: true
      redaction_text: "[REDACTED]"
      field_allowlist:
        - allowed
"#,
        payload,
    )
    .await;

    assert!(result.continue_processing);
    assert!(result.violation.is_none());
    let payload = pipeline_payload(&result);
    assert_eq!(
        prompt_argument(payload, "allowed"),
        &json!("AWS_ACCESS_KEY_ID=[REDACTED]")
    );
    assert_eq!(
        prompt_argument(payload, "ignored"),
        &json!("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")
    );
    println!("prompt-filter passed");
}

async fn tool_allow_deny_smoke() {
    let manager = load_manager(
        "cmf.tool_pre_invoke",
        r#"      block_on_detection: false
      redact: true
      redaction_text: "[REDACTED]"
      field_allowlist:
        - accounts
      field_denylist:
        - accounts.skip
"#,
    )
    .await
    .expect("valid config should load");

    let payload = tool_call_payload(HashMap::from([
        (
            "accounts".to_string(),
            json!({
                "keep": "AWS_ACCESS_KEY_ID=AKIATEST12345EXAMPLE",
                "skip": "AWS_ACCESS_KEY_ID=AKIASKIP12345EXAMPLE"
            }),
        ),
        (
            "ignored".to_string(),
            json!("AWS_ACCESS_KEY_ID=AKIAIGNR12345EXAMPLE"),
        ),
    ]));
    let original = payload.clone();

    let (result, background) = manager
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, Extensions::default(), None)
        .await;
    background.wait_for_background_tasks().await;

    assert!(result.continue_processing);
    assert!(result.violation.is_none());

    let modified_payload = result
        .modified_payload
        .as_ref()
        .expect("redaction should return modified payload")
        .as_any()
        .downcast_ref::<MessagePayload>()
        .expect("expected CMF MessagePayload");
    let modified_args = tool_call_arguments(modified_payload);
    let original_args = tool_call_arguments(&original);

    assert_eq!(
        modified_args["accounts"]["keep"],
        json!("AWS_ACCESS_KEY_ID=[REDACTED]")
    );
    assert_eq!(
        modified_args["accounts"]["skip"],
        json!("AWS_ACCESS_KEY_ID=AKIASKIP12345EXAMPLE")
    );
    assert_eq!(
        modified_args["ignored"],
        json!("AWS_ACCESS_KEY_ID=AKIAIGNR12345EXAMPLE")
    );
    assert_eq!(
        original_args["accounts"]["keep"],
        json!("AWS_ACCESS_KEY_ID=AKIATEST12345EXAMPLE")
    );

    println!(
        "original args:\n{}",
        serde_json::to_string_pretty(original_args).unwrap()
    );
    println!(
        "modified args:\n{}",
        serde_json::to_string_pretty(modified_args).unwrap()
    );
    println!("tool-allow-deny passed");
}

async fn tool_result_filter_smoke() {
    let payload = tool_result_payload(json!({
        "allowed": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",
        "ignored": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
    }));

    let result = invoke_manager(
        "cmf.tool_post_invoke",
        r#"      block_on_detection: false
      redact: true
      redaction_text: "[REDACTED]"
      field_allowlist:
        - allowed
"#,
        payload,
    )
    .await;

    assert!(result.continue_processing);
    assert!(result.violation.is_none());
    let content = tool_result_content(pipeline_payload(&result));
    assert_eq!(content["allowed"], json!("AWS_ACCESS_KEY_ID=[REDACTED]"));
    assert_eq!(
        content["ignored"],
        json!("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")
    );
    println!("tool-result-filter passed");
}

async fn resource_block_smoke() {
    let payload = resource_payload("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE");

    let result = invoke_manager(
        "cmf.resource_post_fetch",
        r#"      block_on_detection: true
      redact: false
      min_findings_to_block: 1
"#,
        payload,
    )
    .await;

    assert!(!result.continue_processing);
    assert_eq!(result.violation.as_ref().unwrap().code, "SECRETS_DETECTED");
    assert!(result.modified_payload.is_none());
    println!("resource-block passed");
}

async fn invoke_manager(hook: &str, config_block: &str, payload: MessagePayload) -> PipelineResult {
    let manager = load_manager(hook, config_block)
        .await
        .expect("config should load");
    let (result, background) = manager
        .invoke_named::<CmfHook>(hook, payload, Extensions::default(), None)
        .await;
    background.wait_for_background_tasks().await;
    result
}

async fn load_manager(hook: &str, config_block: &str) -> Result<Arc<PluginManager>, String> {
    let manager = Arc::new(PluginManager::default());
    manager.register_factory(KIND, Box::new(SecretsDetectionFactory));
    manager
        .load_config_yaml(&plugin_yaml(hook, config_block))
        .map_err(|err| format!("load failed: {err}"))?;
    manager
        .initialize()
        .await
        .map_err(|err| format!("initialize failed: {err}"))?;
    Ok(manager)
}

fn plugin_yaml(hook: &str, config_block: &str) -> String {
    format!(
        r#"plugins:
  - name: secrets-detection
    kind: validator/secrets-detection
    hooks: ["{hook}"]
    mode: sequential
    config:
{config_block}"#
    )
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

fn tool_call_arguments(payload: &MessagePayload) -> &HashMap<String, Value> {
    let ContentPart::ToolCall { content } = &payload.message.content[0] else {
        panic!("expected tool call content");
    };
    &content.arguments
}

fn tool_call_argument<'a>(payload: &'a MessagePayload, key: &str) -> &'a Value {
    tool_call_arguments(payload)
        .get(key)
        .expect("argument exists")
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
