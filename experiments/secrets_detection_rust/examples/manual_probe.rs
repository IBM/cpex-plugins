// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;

use cpex::PluginManager;
use cpex_core::extensions::RequestExtension;
use cpex_sdk::{
    CmfHook, ContentPart, Extensions, Message, MessagePayload, PromptRequest, Resource,
    ResourceType, Role, ToolCall, ToolResult,
};
use secrets_detection_rust::{SecretsDetectionFactory, KIND};
use serde_json::{json, Value};

struct Scenario {
    hook: &'static str,
    config_block: &'static str,
    payload: MessagePayload,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let scenario_name = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tool-redact".to_string());

    let scenario = match scenario_name.as_str() {
        "tool-redact" => tool_redact(),
        "tool-block" => tool_block(),
        "prompt-filter" => prompt_filter(),
        "tool-result-filter" => tool_result_filter(),
        "resource-block" => resource_block(),
        _ => {
            eprintln!("unknown scenario: {scenario_name}");
            eprintln!("available: tool-redact, tool-block, prompt-filter, tool-result-filter, resource-block");
            std::process::exit(2);
        }
    };

    let manager = Arc::new(PluginManager::default());
    manager.register_factory(KIND, Box::new(SecretsDetectionFactory));
    manager
        .load_config_yaml(&plugin_yaml(scenario.hook, scenario.config_block))
        .expect("config should load");
    manager
        .initialize()
        .await
        .expect("manager should initialize");

    let (result, background) = manager
        .invoke_named::<CmfHook>(
            scenario.hook,
            scenario.payload,
            extensions_with_trace("manual-trace-1"),
            None,
        )
        .await;
    background.wait_for_background_tasks().await;

    println!("scenario: {scenario_name}");
    println!("hook: {}", scenario.hook);
    println!("continue_processing: {}", result.continue_processing);
    println!(
        "violation: {}",
        result
            .violation
            .as_ref()
            .map(|violation| violation.code.as_str())
            .unwrap_or("none")
    );
    println!("metadata: {:?}", result.metadata);

    let Some(payload) = result.modified_payload.as_ref() else {
        println!("modified_payload: none");
        return;
    };
    let payload = payload
        .as_any()
        .downcast_ref::<MessagePayload>()
        .expect("expected CMF MessagePayload");

    print_message_payload(payload);
}

fn tool_redact() -> Scenario {
    Scenario {
        hook: "cmf.tool_pre_invoke",
        config_block: r#"      block_on_detection: false
      redact: true
      redaction_text: "[REDACTED]"
"#,
        payload: tool_call_payload(HashMap::from([(
            "token".to_string(),
            json!("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
        )])),
    }
}

fn tool_block() -> Scenario {
    Scenario {
        hook: "cmf.tool_pre_invoke",
        config_block: r#"      block_on_detection: true
      redact: false
      min_findings_to_block: 1
"#,
        payload: tool_call_payload(HashMap::from([(
            "token".to_string(),
            json!("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
        )])),
    }
}

fn prompt_filter() -> Scenario {
    Scenario {
        hook: "cmf.prompt_pre_fetch",
        config_block: r#"      block_on_detection: false
      redact: true
      redaction_text: "[REDACTED]"
      field_allowlist:
        - allowed
"#,
        payload: prompt_request_payload(HashMap::from([
            (
                "allowed".to_string(),
                json!("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
            ),
            (
                "ignored".to_string(),
                json!("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
            ),
        ])),
    }
}

fn tool_result_filter() -> Scenario {
    Scenario {
        hook: "cmf.tool_post_invoke",
        config_block: r#"      block_on_detection: false
      redact: true
      redaction_text: "[REDACTED]"
      field_allowlist:
        - allowed
"#,
        payload: tool_result_payload(json!({
            "allowed": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",
            "ignored": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
        })),
    }
}

fn resource_block() -> Scenario {
    Scenario {
        hook: "cmf.resource_post_fetch",
        config_block: r#"      block_on_detection: true
      redact: false
      min_findings_to_block: 1
"#,
        payload: resource_payload("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
    }
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

fn print_message_payload(payload: &MessagePayload) {
    for part in &payload.message.content {
        match part {
            ContentPart::ToolCall { content } => {
                println!(
                    "tool arguments:\n{}",
                    serde_json::to_string_pretty(&content.arguments).unwrap()
                );
            }
            ContentPart::PromptRequest { content } => {
                println!(
                    "prompt arguments:\n{}",
                    serde_json::to_string_pretty(&content.arguments).unwrap()
                );
            }
            ContentPart::ToolResult { content } => {
                println!(
                    "tool result content:\n{}",
                    serde_json::to_string_pretty(&content.content).unwrap()
                );
            }
            ContentPart::Resource { content } => {
                println!(
                    "resource content: {}",
                    content.content.as_deref().unwrap_or("<none>")
                );
            }
            other => {
                println!("unhandled content part: {other:?}");
            }
        }
    }
}
