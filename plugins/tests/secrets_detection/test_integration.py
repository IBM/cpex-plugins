import pytest
from unittest.mock import AsyncMock, MagicMock

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
