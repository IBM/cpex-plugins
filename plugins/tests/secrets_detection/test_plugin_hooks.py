import pytest

from secrets_detection.helpers import *  # noqa: F403,F405


@pytest.mark.asyncio
class TestPluginHooks:
    @pytest.fixture
    def plugin(self):
        return SecretsDetectionPlugin(make_config())

    async def test_prompt_pre_fetch_redacts_without_blocking(self, plugin):
        payload = PromptPrehookPayload(
            prompt_id="prompt-1",
            args={"input": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"},
        )

        result = await plugin.prompt_pre_fetch(payload, make_context())

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

        result = await plugin.prompt_pre_fetch(payload, make_context())

        assert result.continue_processing is True
        assert result.violation is None
        assert result.modified_payload is None
        assert result.metadata == {}

    async def test_prompt_pre_fetch_blocks_without_redaction(self):
        plugin = SecretsDetectionPlugin(make_config(block_on_detection=True, redact=False))
        payload = PromptPrehookPayload(
            prompt_id="prompt-1",
            args={"input": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"},
        )

        result = await plugin.prompt_pre_fetch(payload, make_context())

        assert result.continue_processing is False
        assert result.violation is not None
        assert result.violation.code == "SECRETS_DETECTED"
        assert result.modified_payload == payload

    async def test_tool_pre_invoke_redacts_arguments_without_blocking(self, plugin):
        payload = ToolPreInvokePayload(
            name="echo",
            args={"message": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"},
        )

        result = await plugin.tool_pre_invoke(payload, make_context())

        assert result.continue_processing is True
        assert result.violation is None
        assert result.modified_payload is not None
        assert result.modified_payload is not payload
        assert (
            result.modified_payload.args["message"]
            == "AWS_ACCESS_KEY_ID=[REDACTED]"
        )
        assert payload.args["message"] == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
        assert result.metadata == {"secrets_redacted": True, "count": 1}

    async def test_tool_pre_invoke_detects_copy_on_write_dict_arguments(self):
        class CopyOnWriteDict(dict):
            def __init__(self, original):
                super().__init__()
                self._original = original

            def __getitem__(self, key):
                return super().__getitem__(key) if key in self else self._original[key]

            def __iter__(self):
                return iter(self._original)

            def __len__(self):
                return len(self._original)

            def items(self):
                return ((key, self[key]) for key in self)

        plugin = SecretsDetectionPlugin(make_config(block_on_detection=True, redact=True))
        payload = ToolPreInvokePayload(
            name="echo",
            args=CopyOnWriteDict(
                {"message": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"}
            ),
        )

        result = await plugin.tool_pre_invoke(payload, make_context())

        assert result.continue_processing is False
        assert result.violation is not None
        assert result.violation.code == "SECRETS_DETECTED"
        assert result.modified_payload is not None
        assert result.modified_payload.args["message"] == "AWS_ACCESS_KEY_ID=[REDACTED]"

    async def test_tool_pre_invoke_leaves_clean_payload_unmodified(self, plugin):
        payload = ToolPreInvokePayload(
            name="echo",
            args={"message": "hello world"},
        )

        result = await plugin.tool_pre_invoke(payload, make_context())

        assert result.continue_processing is True
        assert result.violation is None
        assert result.modified_payload is None
        assert result.metadata == {}

    async def test_tool_pre_invoke_blocks_without_redaction(self):
        plugin = SecretsDetectionPlugin(make_config(block_on_detection=True, redact=False))
        payload = ToolPreInvokePayload(
            name="echo",
            args={"message": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"},
        )

        result = await plugin.tool_pre_invoke(payload, make_context())

        assert result.continue_processing is False
        assert result.violation is not None
        assert result.violation.code == "SECRETS_DETECTED"
        assert result.violation.description == (
            "Potential secrets detected in tool arguments"
        )
        assert result.modified_payload == payload

    async def test_tool_pre_invoke_blocks_with_redaction_without_leaking_secret(self):
        plugin = SecretsDetectionPlugin(make_config(block_on_detection=True, redact=True))
        payload = ToolPreInvokePayload(
            name="echo",
            args={"message": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"},
        )

        result = await plugin.tool_pre_invoke(payload, make_context())

        assert result.continue_processing is False
        assert result.violation is not None
        assert result.violation.code == "SECRETS_DETECTED"
        assert result.modified_payload is not None
        assert result.modified_payload is not payload
        assert result.modified_payload.args["message"] == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert payload.args["message"] == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"

    async def test_prompt_pre_fetch_blocks_with_redaction_without_leaking_secret(self):
        plugin = SecretsDetectionPlugin(make_config(block_on_detection=True, redact=True))
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

    async def test_prompt_pre_fetch_metadata_omits_match_previews(self):
        plugin = SecretsDetectionPlugin(make_config(redact=False))
        payload = PromptPrehookPayload(
            prompt_id="prompt-1",
            args={"input": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"},
        )

        result = await plugin.prompt_pre_fetch(payload, make_context())

        assert result.metadata is not None
        assert result.metadata["count"] == 1
        assert result.metadata["secrets_findings"] == [{"type": "aws_access_key_id"}]

    async def test_prompt_pre_fetch_blocking_details_omit_match_previews(self):
        plugin = SecretsDetectionPlugin(make_config(block_on_detection=True, redact=False))
        payload = PromptPrehookPayload(
            prompt_id="prompt-1",
            args={"input": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"},
        )

        result = await plugin.prompt_pre_fetch(payload, make_context())

        assert result.violation is not None
        assert result.violation.details == {
            "count": 1,
            "examples": [{"type": "aws_access_key_id"}],
        }
