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

#[tokio::test]
async fn prompt_pre_fetch_blocks_without_redaction() {
    let payload = prompt_request_payload(HashMap::from([(
        "token".to_string(),
        json!("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
    )]));

    let result = invoke_manager(
        "cmf.prompt_pre_fetch",
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
}

#[tokio::test]
async fn prompt_pre_fetch_clean_payload_allows_without_modification() {
    let payload = prompt_request_payload(HashMap::from([("message".to_string(), json!("hello"))]));

    let result = invoke_manager(
        "cmf.prompt_pre_fetch",
        r#"      block_on_detection: true
      redact: true
"#,
        payload,
    )
    .await;

    assert!(result.continue_processing);
    assert!(result.violation.is_none());
    assert_eq!(
        prompt_argument(pipeline_payload(&result), "message"),
        &json!("hello")
    );
}

#[tokio::test]
async fn prompt_pre_fetch_field_filters_apply_to_arguments() {
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
    let payload = pipeline_payload(&result);
    assert_eq!(
        prompt_argument(payload, "allowed"),
        &json!("AWS_ACCESS_KEY_ID=[REDACTED]")
    );
    assert_eq!(
        prompt_argument(payload, "ignored"),
        &json!("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")
    );
}

#[tokio::test]
async fn tool_pre_invoke_redacts_without_blocking() {
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
}

#[tokio::test]
async fn tool_pre_invoke_blocks_without_redaction() {
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
}

#[tokio::test]
async fn tool_pre_invoke_clean_payload_allows_without_modification() {
    let payload = tool_call_payload(HashMap::from([("message".to_string(), json!("hello"))]));

    let result = invoke_manager(
        "cmf.tool_pre_invoke",
        r#"      block_on_detection: true
      redact: true
"#,
        payload,
    )
    .await;

    assert!(result.continue_processing);
    assert!(result.violation.is_none());
    assert_eq!(
        tool_call_argument(pipeline_payload(&result), "message"),
        &json!("hello")
    );
}

#[tokio::test]
async fn tool_pre_invoke_rejects_invalid_field_allowlist_at_load() {
    let manager = Arc::new(PluginManager::default());
    manager.register_factory(KIND, Box::new(SecretsDetectionFactory));
    let yaml = plugin_yaml(
        "cmf.tool_pre_invoke",
        r#"      field_allowlist:
        - bad.
"#,
    );

    let err = match manager.load_config_yaml(&yaml) {
        Ok(_) => panic!("invalid field_allowlist should fail config loading"),
        Err(err) => err.to_string(),
    };

    assert!(
        err.contains("field_allowlist path \"bad.\" must not start or end with '.'"),
        "unexpected config error: {err}"
    );
}

#[tokio::test]
async fn tool_pre_invoke_nested_filters_match_crate_smoke() {
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

    let result = invoke_manager(
        "cmf.tool_pre_invoke",
        r#"      block_on_detection: false
      redact: true
      redaction_text: "[REDACTED]"
      field_allowlist:
        - accounts
      field_denylist:
        - accounts.skip
"#,
        payload,
    )
    .await;

    assert!(result.continue_processing);
    assert!(result.violation.is_none());

    let modified = pipeline_payload(&result);
    assert_eq!(
        tool_call_argument(modified, "accounts")["keep"],
        json!("AWS_ACCESS_KEY_ID=[REDACTED]")
    );
    assert_eq!(
        tool_call_argument(modified, "accounts")["skip"],
        json!("AWS_ACCESS_KEY_ID=AKIASKIP12345EXAMPLE")
    );
    assert_eq!(
        tool_call_argument(modified, "ignored"),
        &json!("AWS_ACCESS_KEY_ID=AKIAIGNR12345EXAMPLE")
    );
    assert_eq!(
        tool_call_argument(&original, "accounts")["keep"],
        json!("AWS_ACCESS_KEY_ID=AKIATEST12345EXAMPLE")
    );
}

#[tokio::test]
async fn tool_post_invoke_blocks_json_content() {
    let payload = tool_result_payload(json!({
        "token": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
    }));

    let result = invoke_manager(
        "cmf.tool_post_invoke",
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
}

#[tokio::test]
async fn tool_post_invoke_field_filters_apply_to_result_content() {
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
    let content = tool_result_content(pipeline_payload(&result));
    assert_eq!(content["allowed"], json!("AWS_ACCESS_KEY_ID=[REDACTED]"));
    assert_eq!(
        content["ignored"],
        json!("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")
    );
}

#[tokio::test]
async fn tool_post_invoke_clean_result_allows_without_modification() {
    let payload = tool_result_payload(json!({ "message": "hello" }));

    let result = invoke_manager(
        "cmf.tool_post_invoke",
        r#"      block_on_detection: true
      redact: true
"#,
        payload,
    )
    .await;

    assert!(result.continue_processing);
    assert!(result.violation.is_none());
    assert_eq!(
        tool_result_content(pipeline_payload(&result))["message"],
        json!("hello")
    );
}

#[tokio::test]
async fn resource_post_fetch_blocks_text_content() {
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
}

#[tokio::test]
async fn resource_post_fetch_clean_payload_allows_without_modification() {
    let payload = resource_payload("hello");

    let result = invoke_manager(
        "cmf.resource_post_fetch",
        r#"      block_on_detection: true
      redact: true
"#,
        payload,
    )
    .await;

    assert!(result.continue_processing);
    assert!(result.violation.is_none());
    assert_eq!(resource_text(pipeline_payload(&result)), "hello");
}

async fn invoke_manager(hook: &str, config_block: &str, payload: MessagePayload) -> PipelineResult {
    let manager = Arc::new(PluginManager::default());
    manager.register_factory(KIND, Box::new(SecretsDetectionFactory));
    let yaml = plugin_yaml(hook, config_block);
    manager.load_config_yaml(&yaml).expect("config should load");
    manager.initialize().await.expect("initialize");

    let (result, background) = manager
        .invoke_named::<CmfHook>(hook, payload, Extensions::default(), None)
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
