import pytest

from cpex.framework.extensions import Extensions, RequestExtension
from cpex.framework.hooks.policies import HookPayloadPolicy, apply_policy
from cpex.framework.memory import wrap_payload_for_isolation

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
        # No extensions/trace_id passed => gated, no metadata write at all.
        assert result.metadata == {}

    async def test_prompt_pre_fetch_redaction_survives_cpex_policy_with_isolated_payload(self, plugin):
        payload = PromptPrehookPayload(
            prompt_id="prompt-1",
            args={"input": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"},
        )
        plugin_input = wrap_payload_for_isolation(payload)

        result = await plugin.prompt_pre_fetch(plugin_input, make_context())

        assert result.modified_payload is not None
        filtered = apply_policy(
            plugin_input,
            result.modified_payload,
            HookPayloadPolicy(writable_fields=frozenset({"args"})),
            apply_to=payload,
        )
        assert filtered is not None
        assert payload.args["input"] == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
        assert filtered.args["input"] == "AWS_ACCESS_KEY_ID=[REDACTED]"

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
        # No extensions/trace_id passed here => gated, no metadata write at
        # all. See test_tool_pre_invoke_metadata_omits_match_previews below
        # for the in-scope, trace_id-present case.
        assert result.metadata == {}

    async def test_tool_pre_invoke_redaction_survives_cpex_policy_with_isolated_payload(self, plugin):
        payload = ToolPreInvokePayload(
            name="echo",
            args={"message": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"},
        )
        plugin_input = wrap_payload_for_isolation(payload)

        result = await plugin.tool_pre_invoke(plugin_input, make_context())

        assert result.modified_payload is not None
        filtered = apply_policy(
            plugin_input,
            result.modified_payload,
            HookPayloadPolicy(writable_fields=frozenset({"args"})),
            apply_to=payload,
        )
        assert filtered is not None
        assert payload.args["message"] == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
        assert filtered.args["message"] == "AWS_ACCESS_KEY_ID=[REDACTED]"

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
        ext = Extensions(request=RequestExtension(trace_id="t1"))
        payload = PromptPrehookPayload(
            prompt_id="prompt-1",
            args={"input": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"},
        )

        result = await plugin.prompt_pre_fetch(payload, make_context(), ext)

        assert result.metadata is not None
        metrics = result.metadata["secrets_detection"]
        assert metrics["total_detections"] == 1
        assert metrics["secret_types"] == ["aws_access_key_id"]
        # S1: no raw secret value anywhere in the metrics dict.
        assert "AKIAFAKE12345EXAMPLE" not in str(metrics)

    async def test_prompt_pre_fetch_without_extensions_emits_no_metadata(self):
        plugin = SecretsDetectionPlugin(make_config(redact=False))
        payload = PromptPrehookPayload(
            prompt_id="prompt-1",
            args={"input": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"},
        )

        # Legacy 2-arg call (no `extensions`) must not error (back-compat).
        result = await plugin.prompt_pre_fetch(payload, make_context())

        assert result.metadata == {}

    async def test_tool_pre_invoke_metadata_omits_match_previews(self):
        """Regression test for issue #129 finding 4: tool_pre_invoke now
        accepts `extensions` and emits result.metadata["secrets_detection"]
        under the same contract as the other 3 hooks."""
        plugin = SecretsDetectionPlugin(make_config(redact=False))
        ext = Extensions(request=RequestExtension(trace_id="t1"))
        payload = ToolPreInvokePayload(
            name="echo",
            args={"message": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"},
        )

        result = await plugin.tool_pre_invoke(payload, make_context(), ext)

        assert result.metadata is not None
        metrics = result.metadata["secrets_detection"]
        assert metrics["total_detections"] == 1
        assert metrics["secret_types"] == ["aws_access_key_id"]
        # S1: no raw secret value anywhere in the metrics dict.
        assert "AKIAFAKE12345EXAMPLE" not in str(metrics)

    async def test_prompt_pre_fetch_legacy_flat_keys_are_gone(self):
        plugin = SecretsDetectionPlugin(make_config(redact=False))
        ext = Extensions(request=RequestExtension(trace_id="t1"))
        payload = PromptPrehookPayload(
            prompt_id="prompt-1",
            args={"input": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"},
        )

        result = await plugin.prompt_pre_fetch(payload, make_context(), ext)

        assert "secrets_redacted" not in result.metadata
        assert "secrets_findings" not in result.metadata
        assert "count" not in result.metadata

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
