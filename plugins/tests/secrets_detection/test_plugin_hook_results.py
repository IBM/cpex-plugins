import pytest

from secrets_detection.helpers import *  # noqa: F403,F405


@pytest.mark.asyncio
class TestPluginHookResults:
    @pytest.fixture
    def plugin(self):
        return SecretsDetectionPlugin(make_config())

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

        result = await plugin.tool_post_invoke(payload, make_context())

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

        result = await plugin.tool_post_invoke(payload, make_context())

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

        result = await plugin.tool_post_invoke(payload, make_context())

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

        result = await plugin.tool_post_invoke(payload, make_context())

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

        result = await plugin.tool_post_invoke(payload, make_context())

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

        result = await plugin.tool_post_invoke(payload, make_context())

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

        plugin = SecretsDetectionPlugin(make_config(block_on_detection=True, redact=False))
        payload = ToolPostInvokePayload(
            name="writer",
            result=SplitSecretModel(prefix="AKIA", suffix="FAKE12345EXAMPLE"),
        )

        result = await plugin.tool_post_invoke(payload, make_context())

        assert result.continue_processing is False
        assert result.violation is not None
        assert result.violation.code == "SECRETS_DETECTED"

    async def test_tool_post_invoke_does_not_double_count_model_dump_fields(self):
        class SecretModel(BaseModel):
            text: str

        plugin = SecretsDetectionPlugin(
            make_config(block_on_detection=True, redact=False, min_findings_to_block=2)
        )
        payload = ToolPostInvokePayload(
            name="writer",
            result=SecretModel(text="AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
        )

        result = await plugin.tool_post_invoke(payload, make_context())

        assert result.continue_processing is True
        assert result.violation is None
        assert result.metadata == {
            "count": 1,
            "secrets_findings": [{"type": "aws_access_key_id"}],
        }

    async def test_tool_post_invoke_does_not_double_count_model_dump_list_fields(self):
        class SecretListModel(BaseModel):
            items: list[str]

        plugin = SecretsDetectionPlugin(
            make_config(block_on_detection=True, redact=False, min_findings_to_block=2)
        )
        payload = ToolPostInvokePayload(
            name="writer",
            result=SecretListModel(items=["AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"]),
        )

        result = await plugin.tool_post_invoke(payload, make_context())

        assert result.continue_processing is True
        assert result.violation is None
        assert result.metadata == {
            "count": 1,
            "secrets_findings": [{"type": "aws_access_key_id"}],
        }

    async def test_tool_post_invoke_does_not_double_count_root_model(self):
        plugin = SecretsDetectionPlugin(
            make_config(block_on_detection=True, redact=False, min_findings_to_block=2)
        )
        payload = ToolPostInvokePayload(
            name="writer",
            result=RootModel[str]("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
        )

        result = await plugin.tool_post_invoke(payload, make_context())

        assert result.continue_processing is True
        assert result.violation is None
        assert result.metadata == {
            "count": 1,
            "secrets_findings": [{"type": "aws_access_key_id"}],
        }

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

        result = await plugin.tool_post_invoke(payload, make_context())

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

        result = await plugin.tool_post_invoke(payload, make_context())

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

        result = await plugin.tool_post_invoke(payload, make_context())

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

        result = await plugin.resource_post_fetch(payload, make_context())

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

        result = await plugin.resource_post_fetch(payload, make_context())

        assert result.continue_processing is True
        assert result.violation is None
        assert result.modified_payload is None
        assert result.metadata == {}

    async def test_resource_post_fetch_blocks_when_threshold_met(self):
        plugin = SecretsDetectionPlugin(
            make_config(block_on_detection=True, redact=False, min_findings_to_block=1)
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

        result = await plugin.resource_post_fetch(payload, make_context())

        assert result.continue_processing is False
        assert result.violation is not None
        assert result.violation.code == "SECRETS_DETECTED"
        assert result.modified_payload == payload
