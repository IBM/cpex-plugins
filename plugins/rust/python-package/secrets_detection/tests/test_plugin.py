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
        assert result.modified_payload == payload

    async def test_prompt_pre_fetch_blocks_with_redaction_without_leaking_secret(self):
        plugin = SecretsDetectionPlugin(_make_config(block_on_detection=True, redact=True))
        payload = PromptPrehookPayload(
            prompt_id="prompt-1",
            args={"input": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"},
        )

        result = await plugin.prompt_pre_fetch(payload, _make_context())

        assert result.continue_processing is False
        assert result.violation is not None
        assert result.violation.code == "SECRETS_DETECTED"
        assert result.modified_payload is not None
        assert result.modified_payload is not payload
        assert result.modified_payload.args["input"] == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert payload.args["input"] == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"


class TestPublicRustApi:
    def test_scan_container_preserves_tuple_shape_when_clean(self):
        payload = ("safe", 1, {"nested": "value"})

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 0
        assert findings == []
        assert redacted == payload
        assert isinstance(redacted, tuple)

    def test_scan_container_preserves_opaque_object_when_clean(self):
        class SlotOnlyPayload:
            __slots__ = ("value",)

            def __init__(self, value):
                self.value = value

        payload = SlotOnlyPayload("safe")

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 0
        assert findings == []
        assert redacted is payload

    def test_scan_container_redacts_custom_object_with_dict_state(self):
        class SecretBox:
            def __init__(self, value):
                self.value = value

        payload = SecretBox("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert redacted is not payload
        assert isinstance(redacted, SecretBox)
        assert redacted.value == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert payload.value == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"

    def test_scan_container_redacts_non_replayable_custom_object(self):
        class NonReplayableBox:
            def __init__(self, secret):
                self.secret = secret
                self.derived = "derived"

        payload = NonReplayableBox("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert redacted is not payload
        assert isinstance(redacted, NonReplayableBox)
        assert redacted.secret == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert redacted.derived == "derived"
        assert payload.secret == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"

    def test_scan_container_redacts_slot_backed_custom_object(self):
        class SlotSecretBox:
            __slots__ = ("value",)

            def __init__(self, value):
                self.value = value

        payload = SlotSecretBox("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert redacted is not payload
        assert isinstance(redacted, SlotSecretBox)
        assert redacted.value == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert payload.value == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"

    def test_scan_container_redacts_hybrid_dict_and_slots_object(self):
        class HybridSecretBox:
            __slots__ = {"slot_secret": "slot", "__dict__": "dict"}

            def __init__(self, slot_secret, label):
                self.slot_secret = slot_secret
                self.label = label

        payload = HybridSecretBox(
            "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",
            "safe",
        )

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert redacted is not payload
        assert isinstance(redacted, HybridSecretBox)
        assert redacted.slot_secret == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert redacted.label == "safe"
        assert payload.slot_secret == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"

    def test_scan_container_redacts_guarded_object_without_running_setattr(self):
        class GuardedSecretBox:
            __slots__ = ("secret", "label", "_locked")

            def __init__(self, secret, label):
                object.__setattr__(self, "secret", secret)
                object.__setattr__(self, "label", label)
                object.__setattr__(self, "_locked", True)

            def __setattr__(self, name, value):
                raise AssertionError(f"unexpected setattr for {name}")
                object.__setattr__(self, name, value)

        payload = GuardedSecretBox(
            "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",
            "safe",
        )

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert redacted is not payload
        assert isinstance(redacted, GuardedSecretBox)
        assert redacted.secret == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert redacted.label == "safe"
        assert payload.secret == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"

    def test_scan_container_redacts_slots_declared_as_mapping(self):
        class MappingSlotSecretBox:
            __slots__ = {"secret": "slot doc"}

            def __init__(self, secret):
                self.secret = secret

        payload = MappingSlotSecretBox("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert redacted is not payload
        assert isinstance(redacted, MappingSlotSecretBox)
        assert redacted.secret == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert payload.secret == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"


class TestPluginHookResults:
    @pytest.fixture
    def plugin(self):
        return SecretsDetectionPlugin(_make_config())

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

    async def test_tool_post_invoke_preserves_tuple_shape_when_redacted(self, plugin):
        payload = ToolPostInvokePayload(
            name="writer",
            result=("safe", "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
        )

        result = await plugin.tool_post_invoke(payload, _make_context())

        assert result.continue_processing is True
        assert result.modified_payload is not None
        assert isinstance(result.modified_payload.result, tuple)
        assert result.modified_payload.result == ("safe", "AWS_ACCESS_KEY_ID=[REDACTED]")

    async def test_prompt_pre_fetch_redacts_nested_custom_object(self, plugin):
        class SecretBox:
            def __init__(self, value):
                self.value = value

        payload = PromptPrehookPayload(
            prompt_id="prompt-1",
            args={"payload": SecretBox("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")},
        )

        result = await plugin.prompt_pre_fetch(payload, _make_context())

        assert result.continue_processing is True
        assert result.modified_payload is not None
        assert result.modified_payload.args["payload"] is not payload.args["payload"]
        assert result.modified_payload.args["payload"].value == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert payload.args["payload"].value == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"

    async def test_tool_post_invoke_redacts_non_replayable_custom_object(self, plugin):
        class NonReplayableBox:
            def __init__(self, secret):
                self.secret = secret
                self.derived = "derived"

        payload = ToolPostInvokePayload(
            name="writer",
            result=NonReplayableBox("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
        )

        result = await plugin.tool_post_invoke(payload, _make_context())

        assert result.continue_processing is True
        assert result.modified_payload is not None
        assert result.modified_payload.result is not payload.result
        assert result.modified_payload.result.secret == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert result.modified_payload.result.derived == "derived"
        assert payload.result.secret == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"

    async def test_tool_post_invoke_redacts_hybrid_dict_and_slots_object(self, plugin):
        class HybridSecretBox:
            __slots__ = {"slot_secret": "slot", "__dict__": "dict"}

            def __init__(self, slot_secret, label):
                self.slot_secret = slot_secret
                self.label = label

        payload = ToolPostInvokePayload(
            name="writer",
            result=HybridSecretBox(
                "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",
                "safe",
            ),
        )

        result = await plugin.tool_post_invoke(payload, _make_context())

        assert result.continue_processing is True
        assert result.modified_payload is not None
        assert result.modified_payload.result is not payload.result
        assert result.modified_payload.result.slot_secret == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert result.modified_payload.result.label == "safe"
        assert payload.result.slot_secret == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"

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
        assert result.modified_payload == payload
