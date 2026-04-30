import pytest

from secrets_detection.helpers import *  # noqa: F403,F405


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

    async def manager(
        self,
        tmp_path,
        config: dict,
        *,
        hooks: list[str] | None = None,
        mode: str = PluginMode.ENFORCE.value,
    ) -> PluginManager:
        import yaml

        config_path = tmp_path / "secrets_detection.yaml"
        configured_hooks = hooks or [
            PromptHookType.PROMPT_PRE_FETCH.value,
            ToolHookType.TOOL_POST_INVOKE.value,
            ResourceHookType.RESOURCE_POST_FETCH.value,
        ]
        config_path.write_text(
            yaml.safe_dump(
                {
                    "plugins": [
                        {
                            "name": "SecretsDetection",
                            "kind": "cpex_secrets_detection.secrets_detection.SecretsDetectionPlugin",
                            "hooks": configured_hooks,
                            "mode": mode,
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

    async def test_plugin_manager_skips_unconfigured_hooks(self, tmp_path):
        manager = await self.manager(
            tmp_path,
            {"block_on_detection": True, "redact": False},
            hooks=[PromptHookType.PROMPT_PRE_FETCH.value],
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
            assert result is None
        finally:
            await manager.shutdown()

    async def test_permissive_plugin_manager_mode_continues_chain(self, tmp_path):
        import yaml

        config_path = tmp_path / "secrets_detection_chain.yaml"
        plugin_kind = "cpex_secrets_detection.secrets_detection.SecretsDetectionPlugin"
        config_path.write_text(
            yaml.safe_dump(
                {
                    "plugins": [
                        {
                            "name": "PermissiveSecretsDetection",
                            "kind": plugin_kind,
                            "hooks": [ToolHookType.TOOL_POST_INVOKE.value],
                            "mode": PluginMode.PERMISSIVE.value,
                            "priority": 10,
                            "config": {
                                "block_on_detection": True,
                                "redact": False,
                            },
                        },
                        {
                            "name": "EnforcingSecretsDetection",
                            "kind": plugin_kind,
                            "hooks": [ToolHookType.TOOL_POST_INVOKE.value],
                            "mode": PluginMode.ENFORCE.value,
                            "priority": 20,
                            "config": {
                                "block_on_detection": False,
                                "redact": True,
                                "redaction_text": "[REDACTED]",
                            },
                        },
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
            assert result.continue_processing is True
            assert (
                result.modified_payload.result["secret"]
                == "AWS_ACCESS_KEY_ID=[REDACTED]"
            )
        finally:
            await manager.shutdown()

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
