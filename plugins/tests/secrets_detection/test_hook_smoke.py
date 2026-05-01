import pytest

from secrets_detection.helpers import *  # noqa: F403,F405


# Top-level async tests rely on asyncio_mode=auto in plugins/tests/pytest.ini.
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
async def test_resource_post_fetch_scans_resolved_content_not_uri():
    plugin = SecretsDetectionPlugin(make_config())
    payload = ResourcePostFetchPayload(
        uri="file:///tmp/clean-name.txt",
        content=ResourceContent(
            type="resource",
            id="res-1",
            uri="file:///tmp/clean-name.txt",
            text="AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",
        ),
    )

    result = await plugin.resource_post_fetch(payload, make_context())

    assert result.continue_processing is True
    assert result.modified_payload is not None
    assert result.modified_payload.content.text == "AWS_ACCESS_KEY_ID=[REDACTED]"
