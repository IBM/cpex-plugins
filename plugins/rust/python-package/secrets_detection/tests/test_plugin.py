import pytest

from mcpgateway_mock.plugins.framework import (
    GlobalContext,
    PluginConfig,
    PluginContext,
    PromptPrehookPayload,
    ResourceContent,
    ResourcePostFetchPayload,
    ToolPostInvokePayload,
)

from cpex_secrets_detection.secrets_detection import SecretsDetectionPlugin
from cpex_secrets_detection.secrets_detection_rust import py_scan_container


def _make_config(**overrides) -> PluginConfig:
    config = {
        "block_on_detection": False,
        "redact": True,
        "redaction_text": "[REDACTED]",
    }
    config.update(overrides)
    return PluginConfig(name="secrets_detection", config=config)


def _make_context() -> PluginContext:
    return PluginContext(global_context=GlobalContext(user="user-1"))


class TestRustEngine:
    def test_scan_string_detects_and_redacts_aws_key(self):
        count, redacted, findings = py_scan_container(
            "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",
            {"redact": True, "redaction_text": "[REDACTED]"},
        )

        assert count == 1
        assert redacted == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert findings == [{"type": "aws_access_key_id", "match": "AKIAFAKE…"}]

    def test_scan_nested_container_redacts_tool_payload(self):
        count, redacted, findings = py_scan_container(
            {"content": [{"type": "text", "text": "xoxr-fake-000000000-fake000000000-fakefakefakefake"}]},
            {"redact": True},
        )

        assert count >= 1
        assert redacted["content"][0]["text"] == "***REDACTED***"
        assert any(item["type"] == "slack_token" for item in findings)

    def test_broad_patterns_are_opt_in(self):
        count, redacted, findings = py_scan_container(
            "access_token = 'abcdefghijklmnopqrstuvwx'",
            {"redact": True},
        )

        assert count == 0
        assert redacted == "access_token = 'abcdefghijklmnopqrstuvwx'"
        assert findings == []

    def test_explicitly_enabled_broad_pattern_detects(self):
        count, redacted, findings = py_scan_container(
            "access_token = 'abcdefghijklmnopqrstuvwx'",
            {
                "redact": True,
                "enabled": {"generic_api_key_assignment": True},
            },
        )

        assert count == 1
        assert redacted == "***REDACTED***"
        assert findings == [{"type": "generic_api_key_assignment", "match": "access_t…"}]


class TestPluginHooks:
    @pytest.fixture
    def plugin(self):
        return SecretsDetectionPlugin(_make_config())

    async def test_prompt_pre_fetch_redacts_without_blocking(self, plugin):
        payload = PromptPrehookPayload(
            prompt_id="prompt-1",
            args={"input": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"},
        )

        result = await plugin.prompt_pre_fetch(payload, _make_context())

        assert result.continue_processing is True
        assert result.violation is None
        assert result.modified_payload is not None
        assert result.modified_payload.args["input"] == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert result.metadata == {"secrets_redacted": True, "count": 1}

    async def test_prompt_pre_fetch_leaves_clean_payload_unmodified(self, plugin):
        payload = PromptPrehookPayload(
            prompt_id="prompt-1",
            args={"input": "hello world"},
        )

        result = await plugin.prompt_pre_fetch(payload, _make_context())

        assert result.continue_processing is True
        assert result.violation is None
        assert result.modified_payload is None
        assert result.metadata == {}

    async def test_prompt_pre_fetch_blocks_without_redaction(self):
        plugin = SecretsDetectionPlugin(_make_config(block_on_detection=True, redact=False))
        payload = PromptPrehookPayload(
            prompt_id="prompt-1",
            args={"input": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"},
        )

        result = await plugin.prompt_pre_fetch(payload, _make_context())

        assert result.continue_processing is False
        assert result.violation is not None
        assert result.violation.code == "SECRETS_DETECTED"
        assert result.modified_payload is None

    async def test_tool_post_invoke_redacts_mcp_content_payload(self, plugin):
        payload = ToolPostInvokePayload(
            name="writer",
            result={
                "content": [
                    {
                        "type": "text",
                        "text": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",
                    }
                ],
                "isError": False,
            },
        )

        result = await plugin.tool_post_invoke(payload, _make_context())

        assert result.continue_processing is True
        assert result.modified_payload is not None
        assert (
            result.modified_payload.result["content"][0]["text"]
            == "AWS_ACCESS_KEY_ID=[REDACTED]"
        )
        assert result.modified_payload.result["isError"] is False
        assert result.metadata == {"secrets_redacted": True, "count": 1}

    async def test_tool_post_invoke_leaves_clean_payload_unmodified(self, plugin):
        payload = ToolPostInvokePayload(
            name="writer",
            result={
                "content": [{"type": "text", "text": "plain text"}],
                "isError": False,
            },
        )

        result = await plugin.tool_post_invoke(payload, _make_context())

        assert result.continue_processing is True
        assert result.violation is None
        assert result.modified_payload is None
        assert result.metadata == {}

    async def test_resource_post_fetch_redacts_text_content(self, plugin):
        payload = ResourcePostFetchPayload(
            uri="file:///tmp/secret.txt",
            content=ResourceContent(text="SLACK_TOKEN=xoxr-fake-000000000-fake000000000-fakefakefakefake"),
        )

        result = await plugin.resource_post_fetch(payload, _make_context())

        assert result.continue_processing is True
        assert result.modified_payload is not None
        assert result.modified_payload.content.text == "SLACK_TOKEN=[REDACTED]"
        assert result.metadata == {"secrets_redacted": True, "count": 1}

    async def test_resource_post_fetch_leaves_clean_payload_unmodified(self, plugin):
        payload = ResourcePostFetchPayload(
            uri="file:///tmp/secret.txt",
            content=ResourceContent(text="plain text"),
        )

        result = await plugin.resource_post_fetch(payload, _make_context())

        assert result.continue_processing is True
        assert result.violation is None
        assert result.modified_payload is None
        assert result.metadata == {}

    async def test_resource_post_fetch_blocks_when_threshold_met(self):
        plugin = SecretsDetectionPlugin(
            _make_config(block_on_detection=True, redact=False, min_findings_to_block=1)
        )
        payload = ResourcePostFetchPayload(
            uri="file:///tmp/secret.txt",
            content=ResourceContent(text="AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
        )

        result = await plugin.resource_post_fetch(payload, _make_context())

        assert result.continue_processing is False
        assert result.violation is not None
        assert result.violation.code == "SECRETS_DETECTED"
