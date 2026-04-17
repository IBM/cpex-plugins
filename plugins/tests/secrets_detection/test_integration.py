import subprocess
import sys

import pytest
from unittest.mock import AsyncMock, MagicMock
from pydantic import BaseModel, RootModel, model_serializer

from mcpgateway.common.models import ResourceContent
from mcpgateway.plugins.framework import (
    PluginConfig,
    PluginContext,
    PluginManager,
    PluginMode,
    PromptHookType,
    PromptPrehookPayload,
    ResourceHookType,
    ResourcePostFetchPayload,
    ToolPostInvokePayload,
    ToolHookType,
)
from mcpgateway.plugins.framework.models import GlobalContext
from mcpgateway.services.resource_service import ResourceService

from cpex_secrets_detection.secrets_detection import SecretsDetectionPlugin
from cpex_secrets_detection.secrets_detection_rust import py_scan_container


def make_context() -> PluginContext:
    return PluginContext(
        global_context=GlobalContext(request_id="req-secrets", server_id="srv-secrets")
    )


def make_config(**overrides) -> PluginConfig:
    config = {
        "block_on_detection": False,
        "redact": True,
        "redaction_text": "[REDACTED]",
    }
    config.update(overrides)
    return PluginConfig(
        name="secrets_detection",
        kind="cpex_secrets_detection.secrets_detection.SecretsDetectionPlugin",
        config=config,
    )


def _make_context() -> PluginContext:
    return make_context()


def _make_config(**overrides) -> PluginConfig:
    return make_config(**overrides)


@pytest.mark.asyncio
async def test_prompt_pre_fetch_rebuilds_frozen_payload_on_redaction():
    plugin = SecretsDetectionPlugin(make_config())
    payload = PromptPrehookPayload(
        prompt_id="prompt-1",
        args={"input": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"},
    )

    result = await plugin.prompt_pre_fetch(payload, make_context())

    assert result.continue_processing is True
    assert result.modified_payload is not None
    assert result.modified_payload is not payload
    assert result.modified_payload.args["input"] == "AWS_ACCESS_KEY_ID=[REDACTED]"
    assert payload.args["input"] == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"


@pytest.mark.asyncio
async def test_prompt_pre_fetch_blocks_without_redaction_and_keeps_original_payload():
    plugin = SecretsDetectionPlugin(
        make_config(block_on_detection=True, redact=False, min_findings_to_block=1)
    )
    payload = PromptPrehookPayload(
        prompt_id="prompt-1",
        args={"input": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"},
    )

    result = await plugin.prompt_pre_fetch(payload, make_context())

    assert result.continue_processing is False
    assert result.violation is not None
    assert result.violation.code == "SECRETS_DETECTED"
    assert result.modified_payload == payload


@pytest.mark.asyncio
async def test_prompt_pre_fetch_blocks_with_redaction_without_leaking_secret():
    plugin = SecretsDetectionPlugin(
        make_config(block_on_detection=True, redact=True, min_findings_to_block=1)
    )
    payload = PromptPrehookPayload(
        prompt_id="prompt-1",
        args={"input": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"},
    )

    result = await plugin.prompt_pre_fetch(payload, make_context())

    assert result.continue_processing is False
    assert result.violation is not None
    assert result.violation.code == "SECRETS_DETECTED"
    assert result.modified_payload is not None
    assert result.modified_payload is not payload
    assert result.modified_payload.args["input"] == "AWS_ACCESS_KEY_ID=[REDACTED]"
    assert payload.args["input"] == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"


@pytest.mark.asyncio
async def test_tool_post_invoke_rebuilds_frozen_payload_on_redaction():
    plugin = SecretsDetectionPlugin(make_config())
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

    result = await plugin.tool_post_invoke(payload, make_context())

    assert result.continue_processing is True
    assert result.modified_payload is not None
    assert result.modified_payload is not payload
    assert (
        result.modified_payload.result["content"][0]["text"]
        == "AWS_ACCESS_KEY_ID=[REDACTED]"
    )
    assert payload.result["content"][0]["text"] == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"


@pytest.mark.asyncio
async def test_tool_post_invoke_preserves_tuple_shape_when_redacted():
    plugin = SecretsDetectionPlugin(make_config())
    payload = ToolPostInvokePayload(
        name="writer",
        result=("safe", "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
    )

    result = await plugin.tool_post_invoke(payload, make_context())

    assert result.continue_processing is True
    assert result.modified_payload is not None
    assert isinstance(result.modified_payload.result, tuple)
    assert result.modified_payload.result == (
        "safe",
        "AWS_ACCESS_KEY_ID=[REDACTED]",
    )


@pytest.mark.asyncio
async def test_tool_post_invoke_redacts_custom_object_result():
    class SecretBox:
        def __init__(self, value):
            self.value = value

    plugin = SecretsDetectionPlugin(make_config())
    payload = ToolPostInvokePayload(
        name="writer",
        result=SecretBox("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
    )

    result = await plugin.tool_post_invoke(payload, make_context())

    assert result.continue_processing is True
    assert result.modified_payload is not None
    assert result.modified_payload.result is not payload.result
    assert result.modified_payload.result.value == "AWS_ACCESS_KEY_ID=[REDACTED]"
    assert payload.result.value == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"


@pytest.mark.asyncio
async def test_tool_post_invoke_redacts_non_replayable_custom_object_result():
    class NonReplayableBox:
        def __init__(self, secret):
            self.secret = secret
            self.derived = "derived"

    plugin = SecretsDetectionPlugin(make_config())
    payload = ToolPostInvokePayload(
        name="writer",
        result=NonReplayableBox("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
    )

    result = await plugin.tool_post_invoke(payload, make_context())

    assert result.continue_processing is True
    assert result.modified_payload is not None
    assert result.modified_payload.result is not payload.result
    assert result.modified_payload.result.secret == "AWS_ACCESS_KEY_ID=[REDACTED]"
    assert result.modified_payload.result.derived == "derived"
    assert payload.result.secret == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"


@pytest.mark.asyncio
async def test_tool_post_invoke_redacts_slot_backed_custom_object_result():
    class SlotSecretBox:
        __slots__ = ("value",)

        def __init__(self, value):
            self.value = value

    plugin = SecretsDetectionPlugin(make_config())
    payload = ToolPostInvokePayload(
        name="writer",
        result=SlotSecretBox("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
    )

    result = await plugin.tool_post_invoke(payload, make_context())

    assert result.continue_processing is True
    assert result.modified_payload is not None
    assert result.modified_payload.result is not payload.result
    assert result.modified_payload.result.value == "AWS_ACCESS_KEY_ID=[REDACTED]"
    assert payload.result.value == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"


@pytest.mark.asyncio
async def test_resource_post_fetch_rebuilds_frozen_payload_on_redaction():
    plugin = SecretsDetectionPlugin(make_config())
    payload = ResourcePostFetchPayload(
        uri="file:///tmp/secret.txt",
        content=ResourceContent(
            type="resource",
            id="res-1",
            uri="file:///tmp/secret.txt",
            text="SLACK_TOKEN=xoxr-fake-000000000-fake000000000-fakefakefakefake",
        ),
    )

    result = await plugin.resource_post_fetch(payload, make_context())

    assert result.continue_processing is True
    assert result.modified_payload is not None
    assert result.modified_payload is not payload
    assert result.modified_payload.content.text == "SLACK_TOKEN=[REDACTED]"
    assert (
        payload.content.text
        == "SLACK_TOKEN=xoxr-fake-000000000-fake000000000-fakefakefakefake"
    )


@pytest.mark.asyncio
async def test_resource_post_fetch_receives_resolved_content():
    captured = {}

    class CaptureSecretsPlugin(SecretsDetectionPlugin):
        async def resource_post_fetch(self, payload, context):
            captured["text"] = payload.content.text
            return await super().resource_post_fetch(payload, context)

    plugin = CaptureSecretsPlugin(
        PluginConfig(
            name="secrets_detection",
            kind="cpex_secrets_detection.secrets_detection.SecretsDetectionPlugin",
            config={},
        )
    )

    fake_resource = MagicMock()
    fake_resource.id = "res1"
    fake_resource.uri = "file:///data/x.txt"
    fake_resource.enabled = True
    fake_resource.content = ResourceContent(
        type="resource",
        id="res1",
        uri="file:///data/x.txt",
        text="file:///data/x.txt",
    )

    fake_db = MagicMock()
    fake_db.get.return_value = fake_resource
    fake_db.execute.return_value.scalar_one_or_none.return_value = fake_resource

    service = ResourceService()
    service.invoke_resource = AsyncMock(return_value="actual file content")

    pm = MagicMock()
    pm.has_hooks_for.return_value = True
    pm._initialized = True

    async def invoke_hook(
        hook_type,
        payload,
        global_context,
        local_contexts=None,
        violations_as_exceptions=True,
    ):
        del local_contexts, violations_as_exceptions
        if hook_type == ResourceHookType.RESOURCE_POST_FETCH:
            await plugin.resource_post_fetch(payload, global_context)
        return MagicMock(modified_payload=None), None

    pm.invoke_hook = invoke_hook
    service._get_plugin_manager = AsyncMock(return_value=pm)

    result = await service.read_resource(
        db=fake_db,
        resource_id="res1",
        resource_uri="file:///data/x.txt",
    )

    assert captured["text"] == "actual file content"
    assert result.text == "actual file content"


@pytest.mark.asyncio
class TestSecretsDetectionHookDispatch:
    @pytest.fixture(autouse=True)
    def reset_plugin_manager(self):
        PluginManager.reset()
        yield
        PluginManager.reset()

    @staticmethod
    def global_context() -> GlobalContext:
        return GlobalContext(request_id="req-secrets", server_id="srv-secrets")

    async def manager(self, tmp_path, config: dict) -> PluginManager:
        import yaml

        config_path = tmp_path / "secrets_detection.yaml"
        config_path.write_text(
            yaml.safe_dump(
                {
                    "plugins": [
                        {
                            "name": "SecretsDetection",
                            "kind": "cpex_secrets_detection.secrets_detection.SecretsDetectionPlugin",
                            "hooks": [
                                PromptHookType.PROMPT_PRE_FETCH.value,
                                ToolHookType.TOOL_POST_INVOKE.value,
                                ResourceHookType.RESOURCE_POST_FETCH.value,
                            ],
                            "mode": PluginMode.ENFORCE.value,
                            "priority": 100,
                            "config": config,
                        }
                    ],
                    "plugin_dirs": [],
                    "plugin_settings": {
                        "parallel_execution_within_band": False,
                        "plugin_timeout": 30,
                        "fail_on_plugin_error": False,
                        "enable_plugin_api": True,
                        "plugin_health_check_interval": 60,
                    },
                }
            ),
            encoding="utf-8",
        )
        manager = PluginManager(str(config_path))
        await manager.initialize()
        return manager

    async def test_prompt_pre_fetch_blocks_without_redaction_via_plugin_manager(
        self, tmp_path
    ):
        manager = await self.manager(
            tmp_path, {"block_on_detection": True, "redact": False}
        )
        try:
            payload = PromptPrehookPayload(
                prompt_id="prompt-1",
                args={"input": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"},
            )
            result, _ = await manager.invoke_hook(
                PromptHookType.PROMPT_PRE_FETCH,
                payload,
                global_context=self.global_context(),
            )
            assert result.continue_processing is False
            assert result.violation.code == "SECRETS_DETECTED"
            assert result.modified_payload == payload
        finally:
            await manager.shutdown()

    async def test_tool_post_invoke_blocks_without_redaction_via_plugin_manager(
        self, tmp_path
    ):
        manager = await self.manager(
            tmp_path, {"block_on_detection": True, "redact": False}
        )
        try:
            payload = ToolPostInvokePayload(
                name="writer",
                result={"secret": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"},
            )
            result, _ = await manager.invoke_hook(
                ToolHookType.TOOL_POST_INVOKE,
                payload,
                global_context=self.global_context(),
            )
            assert result.continue_processing is False
            assert result.violation.code == "SECRETS_DETECTED"
            assert result.modified_payload == payload
        finally:
            await manager.shutdown()

    async def test_resource_post_fetch_blocks_without_redaction_via_plugin_manager(
        self, tmp_path
    ):
        manager = await self.manager(
            tmp_path, {"block_on_detection": True, "redact": False}
        )
        try:
            payload = ResourcePostFetchPayload(
                uri="file:///tmp/secret.txt",
                content=ResourceContent(
                    type="resource",
                    id="res-1",
                    uri="file:///tmp/secret.txt",
                    text="AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",
                ),
            )
            result, _ = await manager.invoke_hook(
                ResourceHookType.RESOURCE_POST_FETCH,
                payload,
                global_context=self.global_context(),
            )
            assert result.continue_processing is False
            assert result.violation.code == "SECRETS_DETECTED"
            assert result.modified_payload == payload
        finally:
            await manager.shutdown()
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

    async def test_prompt_pre_fetch_metadata_omits_match_previews(self):
        plugin = SecretsDetectionPlugin(_make_config(redact=False))
        payload = PromptPrehookPayload(
            prompt_id="prompt-1",
            args={"input": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"},
        )

        result = await plugin.prompt_pre_fetch(payload, _make_context())

        assert result.metadata is not None
        assert result.metadata["count"] == 1
        assert result.metadata["secrets_findings"] == [{"type": "aws_access_key_id"}]

    async def test_prompt_pre_fetch_blocking_details_omit_match_previews(self):
        plugin = SecretsDetectionPlugin(_make_config(block_on_detection=True, redact=False))
        payload = PromptPrehookPayload(
            prompt_id="prompt-1",
            args={"input": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"},
        )

        result = await plugin.prompt_pre_fetch(payload, _make_context())

        assert result.violation is not None
        assert result.violation.details == {
            "count": 1,
            "examples": [{"type": "aws_access_key_id"}],
        }


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

    def test_scan_container_handles_split_concerns_through_public_api(self):
        class Wrapper:
            def __init__(self, value, back=None):
                self.value = value
                self.back = back

            def model_dump(self):
                return {"value": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE", "back": self.back}

        back_edge = Wrapper("safe")
        payload = ("safe", back_edge)
        back_edge.back = payload

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert findings == [{"type": "aws_access_key_id"}]
        assert isinstance(redacted, tuple)
        assert redacted[0] == "safe"
        assert isinstance(redacted[1], Wrapper)
        assert redacted[1].value == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert redacted[1] is not back_edge
        assert redacted[1].back is redacted
        assert back_edge.value == "safe"
        assert back_edge.back is payload

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
        assert findings == [{"type": "aws_access_key_id"}]
        assert redacted is not payload
        assert isinstance(redacted, SecretBox)
        assert redacted.value == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert payload.value == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"

    def test_scan_container_omits_match_previews_from_public_findings(self):
        count, _, findings = py_scan_container(
            "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",
            {"redact": True, "redaction_text": "[REDACTED]"},
        )

        assert count == 1
        assert findings == [{"type": "aws_access_key_id"}]

    def test_scan_container_prefers_redacted_serialized_view_when_both_paths_match(self):
        class DualSurfacePayload:
            def __init__(self):
                self.state_secret = "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"

            def model_dump(self):
                return "AWS_SECRET_ACCESS_KEY=FAKESecretAccessKeyForTestingEXAMPLE0000"

        payload = DualSurfacePayload()

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 2
        assert findings == [
            {"type": "aws_access_key_id"},
            {"type": "aws_secret_access_key"},
        ]
        assert redacted == "[REDACTED]"

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

    def test_scan_container_detects_secret_exposed_only_by_model_dump(self):
        class SplitSecretModel(BaseModel):
            prefix: str
            suffix: str

            @model_serializer(mode="plain")
            def serialize_model(self):
                return f"{self.prefix}{self.suffix}"

        payload = SplitSecretModel(prefix="AKIA", suffix="FAKE12345EXAMPLE")

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert redacted == "[REDACTED]"

    def test_scan_container_detects_secret_when_model_dump_key_overlaps_internal_state(self):
        class OverlappingStateBox:
            def __init__(self):
                self.secret = "safe"

            def model_dump(self):
                return {"secret": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"}

        payload = OverlappingStateBox()

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert isinstance(redacted, OverlappingStateBox)
        assert redacted.secret == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert payload.secret == "safe"

    def test_scan_container_redacts_secret_exposed_only_by_root_model_dump(self):
        payload = RootModel[str]("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert isinstance(redacted, RootModel)
        assert redacted.root == "AWS_ACCESS_KEY_ID=[REDACTED]"

    def test_scan_container_handles_recursive_model_dump_without_crashing(self):
        script = """
from cpex_secrets_detection.secrets_detection_rust import py_scan_container

class RecursivePayload:
    def __init__(self):
        self.secret = "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"

    def model_dump(self):
        return self

count, redacted, findings = py_scan_container(
    RecursivePayload(),
    {"redact": True, "redaction_text": "[REDACTED]"},
)
assert count == 1
assert len(findings) == 1
assert redacted.secret == "AWS_ACCESS_KEY_ID=[REDACTED]"
"""
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )

        assert result.returncode == 0, result.stderr or result.stdout

    def test_scan_container_redacts_cyclic_dict_without_leaking_original_back_edge(self):
        payload = {}
        payload["secret"] = "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
        payload["self"] = payload

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert redacted["secret"] == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert redacted["self"] is redacted
        assert redacted["self"]["secret"] == "AWS_ACCESS_KEY_ID=[REDACTED]"

    def test_scan_container_redacts_self_referential_object_without_leaking_back_edge(self):
        class SelfReferentialBox:
            def __init__(self, secret):
                self.secret = secret
                self.self_ref = self

        payload = SelfReferentialBox("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert redacted is not payload
        assert redacted.secret == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert redacted.self_ref is redacted
        assert redacted.self_ref.secret == "AWS_ACCESS_KEY_ID=[REDACTED]"

    def test_scan_container_redacts_tuple_cycle_without_leaking_original_back_edge(self):
        back_edge = []
        payload = ("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE", back_edge)
        back_edge.append(payload)

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert isinstance(redacted, tuple)
        assert redacted[0] == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert redacted[1][0] is redacted
        assert redacted[1][0][0] == "AWS_ACCESS_KEY_ID=[REDACTED]"

    def test_scan_container_handles_recursive_model_dump_wrapper_without_crashing(self):
        script = """
from cpex_secrets_detection.secrets_detection_rust import py_scan_container

class WrapperPayload:
    def __init__(self, value):
        self.value = value

    def model_dump(self):
        return WrapperPayload(self.value)

count, redacted, findings = py_scan_container(
    WrapperPayload("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
    {"redact": True, "redaction_text": "[REDACTED]"},
)
assert count == 1
assert len(findings) == 1
assert redacted.value == "AWS_ACCESS_KEY_ID=[REDACTED]"
"""
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )

        assert result.returncode == 0, result.stderr or result.stdout

    def test_scan_container_detects_secret_exposed_only_by_serialized_wrapper_object(self):
        class View:
            def __init__(self, secret):
                self.secret = secret

        class WrappedSerializerModel(BaseModel):
            safe: str

            @model_serializer(mode="plain")
            def serialize_model(self):
                return View("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")

        payload = WrappedSerializerModel(safe="ok")

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert isinstance(redacted, View)
        assert redacted.secret == "AWS_ACCESS_KEY_ID=[REDACTED]"

    def test_scan_container_redacts_self_referential_model_copy_object_without_leak(self):
        class SelfReferentialModel(BaseModel):
            secret: str
            self_ref: "SelfReferentialModel | None" = None

        payload = SelfReferentialModel(secret="AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")
        object.__setattr__(payload, "self_ref", payload)

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert redacted is not payload
        assert isinstance(redacted, SelfReferentialModel)
        assert redacted.secret == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert redacted.self_ref is redacted
        assert redacted.self_ref.secret == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert payload.secret == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
        assert payload.self_ref is payload

    def test_scan_container_does_not_call_model_copy_on_clean_object(self):
        class CountingModel(BaseModel):
            value: str
            copies: int = 0

            def model_copy(self, *, update=None, deep=False):
                object.__setattr__(self, "copies", self.copies + 1)
                return super().model_copy(update=update, deep=deep)

        payload = CountingModel(value="clean")

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 0
        assert findings == []
        assert redacted is payload
        assert payload.copies == 0

    def test_scan_container_detects_secret_exposed_only_by_same_type_serialized_wrapper(self):
        class SameTypeWrapper(BaseModel):
            safe: str

            @model_serializer(mode="plain")
            def serialize_model(self):
                return SameTypeWrapper.model_construct(
                    safe="AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
                )

        payload = SameTypeWrapper(safe="clean")

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert isinstance(redacted, SameTypeWrapper)
        assert redacted.safe == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert payload.safe == "clean"

    def test_scan_container_redacts_same_type_serialized_wrapper_without_model_copy(self):
        class Wrapper:
            def __init__(self, value):
                self.value = value

            def model_dump(self):
                return Wrapper("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")

        payload = Wrapper("clean")

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert isinstance(redacted, Wrapper)
        assert redacted.value == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert payload.value == "clean"

    def test_scan_container_handles_recursive_same_type_wrapper_without_rebuild_state(self):
        script = """
from cpex_secrets_detection.secrets_detection_rust import py_scan_container

class Wrapper:
    __slots__ = ()

    def model_dump(self):
        return Wrapper()

count, redacted, findings = py_scan_container(
    Wrapper(),
    {"redact": True, "redaction_text": "[REDACTED]"},
)
assert count == 0
assert findings == []
assert isinstance(redacted, Wrapper)
"""
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )

        assert result.returncode == 0, result.stderr or result.stdout

    def test_scan_container_handles_tuple_rewrite_with_cyclic_dict_subgraph(self):
        script = """
from cpex_secrets_detection.secrets_detection_rust import py_scan_container

d = {}
payload = ("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE", d)
d["self"] = d

count, redacted, findings = py_scan_container(
    payload,
    {"redact": True, "redaction_text": "[REDACTED]"},
)
assert count == 1
assert redacted[0] == "AWS_ACCESS_KEY_ID=[REDACTED]"
assert redacted[1]["self"] is redacted[1]
"""
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )

        assert result.returncode == 0, result.stderr or result.stdout

    def test_scan_container_rewrites_tuple_cycle_references_inside_custom_objects(self):
        class Box:
            def __init__(self, back):
                self.back = back

        back_edge = Box(None)
        payload = ("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE", back_edge)
        back_edge.back = payload

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert isinstance(redacted, tuple)
        assert isinstance(redacted[1], Box)
        assert redacted[0] == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert redacted[1].back is redacted
        assert redacted[1].back[0] == "AWS_ACCESS_KEY_ID=[REDACTED]"

    def test_scan_container_redacts_slots_declared_as_custom_iterable(self):
        class SlotNames:
            def __iter__(self):
                return iter(("secret",))

        class IterableSlotSecretBox:
            __slots__ = SlotNames()

            def __init__(self, secret):
                self.secret = secret

        payload = IterableSlotSecretBox("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert isinstance(redacted, IterableSlotSecretBox)
        assert redacted.secret == "AWS_ACCESS_KEY_ID=[REDACTED]"


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

    async def test_tool_post_invoke_redacts_guarded_object(self, plugin):
        class GuardedSecretBox:
            __slots__ = ("secret", "label", "_locked")

            def __init__(self, secret, label):
                object.__setattr__(self, "secret", secret)
                object.__setattr__(self, "label", label)
                object.__setattr__(self, "_locked", True)

            def __setattr__(self, name, value):
                raise AssertionError(f"unexpected setattr for {name}")
                object.__setattr__(self, name, value)

        payload = ToolPostInvokePayload(
            name="writer",
            result=GuardedSecretBox(
                "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",
                "safe",
            ),
        )

        result = await plugin.tool_post_invoke(payload, _make_context())

        assert result.continue_processing is True
        assert result.modified_payload is not None
        assert result.modified_payload.result is not payload.result
        assert result.modified_payload.result.secret == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert result.modified_payload.result.label == "safe"

    async def test_tool_post_invoke_redacts_mapping_slot_object(self, plugin):
        class MappingSlotSecretBox:
            __slots__ = {"secret": "slot doc"}

            def __init__(self, secret):
                self.secret = secret

        payload = ToolPostInvokePayload(
            name="writer",
            result=MappingSlotSecretBox("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
        )

        result = await plugin.tool_post_invoke(payload, _make_context())

        assert result.continue_processing is True
        assert result.modified_payload is not None
        assert result.modified_payload.result is not payload.result
        assert result.modified_payload.result.secret == "AWS_ACCESS_KEY_ID=[REDACTED]"

    async def test_tool_post_invoke_blocks_secret_exposed_only_by_model_dump(self):
        class SplitSecretModel(BaseModel):
            prefix: str
            suffix: str

            @model_serializer(mode="plain")
            def serialize_model(self):
                return f"{self.prefix}{self.suffix}"

        plugin = SecretsDetectionPlugin(_make_config(block_on_detection=True, redact=False))
        payload = ToolPostInvokePayload(
            name="writer",
            result=SplitSecretModel(prefix="AKIA", suffix="FAKE12345EXAMPLE"),
        )

        result = await plugin.tool_post_invoke(payload, _make_context())

        assert result.continue_processing is False
        assert result.violation is not None
        assert result.violation.code == "SECRETS_DETECTED"

    async def test_tool_post_invoke_redacts_secret_exposed_only_by_model_dump(self, plugin):
        class SplitSecretModel(BaseModel):
            prefix: str
            suffix: str

            @model_serializer(mode="plain")
            def serialize_model(self):
                return f"{self.prefix}{self.suffix}"

        payload = ToolPostInvokePayload(
            name="writer",
            result=SplitSecretModel(prefix="AKIA", suffix="FAKE12345EXAMPLE"),
        )

        result = await plugin.tool_post_invoke(payload, _make_context())

        assert result.continue_processing is True
        assert result.modified_payload is not None
        assert result.modified_payload.result == "[REDACTED]"
        assert result.metadata == {"secrets_redacted": True, "count": 1}

    async def test_tool_post_invoke_redacts_secret_exposed_only_by_root_model_dump(
        self, plugin
    ):
        payload = ToolPostInvokePayload(
            name="writer",
            result=RootModel[str]("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
        )

        result = await plugin.tool_post_invoke(payload, _make_context())

        assert result.continue_processing is True
        assert result.modified_payload is not None
        assert isinstance(result.modified_payload.result, RootModel)
        assert result.modified_payload.result.root == "AWS_ACCESS_KEY_ID=[REDACTED]"

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
            content=ResourceContent(
                type="resource",
                id="res-1",
                uri="file:///tmp/secret.txt",
                text="SLACK_TOKEN=xoxr-fake-000000000-fake000000000-fakefakefakefake",
            ),
        )

        result = await plugin.resource_post_fetch(payload, _make_context())

        assert result.continue_processing is True
        assert result.modified_payload is not None
        assert result.modified_payload.content.text == "SLACK_TOKEN=[REDACTED]"
        assert result.metadata == {"secrets_redacted": True, "count": 1}

    async def test_resource_post_fetch_leaves_clean_payload_unmodified(self, plugin):
        payload = ResourcePostFetchPayload(
            uri="file:///tmp/secret.txt",
            content=ResourceContent(
                type="resource",
                id="res-1",
                uri="file:///tmp/secret.txt",
                text="plain text",
            ),
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
            content=ResourceContent(
                type="resource",
                id="res-1",
                uri="file:///tmp/secret.txt",
                text="AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",
            ),
        )

        result = await plugin.resource_post_fetch(payload, _make_context())

        assert result.continue_processing is False
        assert result.violation is not None
        assert result.violation.code == "SECRETS_DETECTED"
        assert result.modified_payload == payload
