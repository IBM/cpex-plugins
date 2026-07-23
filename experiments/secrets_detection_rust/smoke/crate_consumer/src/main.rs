// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;

use cpex::PluginManager;
use cpex_sdk::{CmfHook, ContentPart, Extensions, Message, MessagePayload, Role, ToolCall};
use secrets_detection_rust::{SecretsDetectionFactory, KIND};
use serde_json::{json, Value};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    ensure_invalid_config_is_rejected().await;
    field_filter_smoke().await;
    println!("crate-level field filter smoke test passed");
}

async fn ensure_invalid_config_is_rejected() {
    let result = load_manager(
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

async fn field_filter_smoke() {
    let manager = load_manager(
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
}

async fn load_manager(config_block: &str) -> Result<Arc<PluginManager>, String> {
    let manager = Arc::new(PluginManager::default());
    manager.register_factory(KIND, Box::new(SecretsDetectionFactory));
    manager
        .load_config_yaml(&plugin_yaml(config_block))
        .map_err(|err| format!("load failed: {err}"))?;
    manager
        .initialize()
        .await
        .map_err(|err| format!("initialize failed: {err}"))?;
    Ok(manager)
}

fn plugin_yaml(config_block: &str) -> String {
    format!(
        r#"plugins:
  - name: secrets-detection
    kind: validator/secrets-detection
    hooks: ["cmf.tool_pre_invoke"]
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

fn tool_call_arguments(payload: &MessagePayload) -> &HashMap<String, Value> {
    let ContentPart::ToolCall { content } = &payload.message.content[0] else {
        panic!("expected tool call content");
    };
    &content.arguments
}
