import pytest

from secrets_detection.helpers import *  # noqa: F403,F405


def aws_access_key(suffix):
    return "AWS_ACCESS" + "_KEY_ID=" + "AK" + "IA" + suffix


def test_invalid_field_filter_config_fails_at_load():
    with pytest.raises(ValueError, match="field_allowlist.*start or end"):
        SecretsDetectionPlugin(make_config(field_allowlist=["bad."]))


@pytest.mark.asyncio
class TestSecretsDetectionFieldFilters:
    async def test_tool_pre_invoke_allowlist_redacts_only_matching_fields(self):
        plugin = SecretsDetectionPlugin(make_config(field_allowlist=["accounts"]))
        payload = ToolPreInvokePayload(
            name="echo",
            args={
                "accounts": {
                    "primary": aws_access_key("TEST12345EXAMPLE"),
                },
                "ignored": aws_access_key("IGNR12345EXAMPLE"),
            },
        )

        result = await plugin.tool_pre_invoke(payload, make_context())

        assert result.continue_processing is True
        assert result.violation is None
        assert result.modified_payload is not None
        assert (
            result.modified_payload.args["accounts"]["primary"]
            == "AWS_ACCESS_KEY_ID=[REDACTED]"
        )
        assert (
            result.modified_payload.args["ignored"]
            == aws_access_key("IGNR12345EXAMPLE")
        )

    async def test_tool_pre_invoke_denylist_takes_precedence_over_allowlist(self):
        plugin = SecretsDetectionPlugin(
            make_config(
                field_allowlist=["accounts"],
                field_denylist=["accounts.skip"],
            )
        )
        payload = ToolPreInvokePayload(
            name="echo",
            args={
                "accounts": {
                    "keep": aws_access_key("TEST12345EXAMPLE"),
                    "skip": aws_access_key("SKIP12345EXAMPLE"),
                },
            },
        )

        result = await plugin.tool_pre_invoke(payload, make_context())

        assert result.continue_processing is True
        assert result.violation is None
        assert result.modified_payload is not None
        assert (
            result.modified_payload.args["accounts"]["keep"]
            == "AWS_ACCESS_KEY_ID=[REDACTED]"
        )
        assert (
            result.modified_payload.args["accounts"]["skip"]
            == aws_access_key("SKIP12345EXAMPLE")
        )

    async def test_tool_pre_invoke_threshold_counts_only_eligible_fields(self):
        plugin = SecretsDetectionPlugin(
            make_config(
                block_on_detection=True,
                redact=False,
                min_findings_to_block=2,
                field_allowlist=["accounts"],
            )
        )
        payload = ToolPreInvokePayload(
            name="echo",
            args={
                "accounts": aws_access_key("TEST12345EXAMPLE"),
                "ignored": aws_access_key("IGNR12345EXAMPLE"),
            },
        )

        result = await plugin.tool_pre_invoke(payload, make_context())

        assert result.continue_processing is True
        assert result.violation is None
        assert result.modified_payload is None

    async def test_tool_post_invoke_allowlist_is_relative_to_result(self):
        plugin = SecretsDetectionPlugin(
            make_config(field_allowlist=["users.credentials.token"])
        )
        payload = ToolPostInvokePayload(
            name="writer",
            result={
                "users": [
                    {
                        "credentials": {
                            "token": aws_access_key("TEST12345EXAMPLE"),
                            "note": aws_access_key("NOTE12345EXAMPLE"),
                        }
                    },
                    (
                        {
                            "credentials": {
                                "token": aws_access_key("TUPL12345EXAMPLE"),
                            }
                        },
                    ),
                ],
                "token": aws_access_key("ROOT12345EXAMPLE"),
            },
        )

        result = await plugin.tool_post_invoke(payload, make_context())

        assert result.continue_processing is True
        assert result.violation is None
        assert result.modified_payload is not None
        redacted_result = result.modified_payload.result
        assert redacted_result["users"][0]["credentials"]["token"] == (
            "AWS_ACCESS_KEY_ID=[REDACTED]"
        )
        assert redacted_result["users"][0]["credentials"]["note"] == (
            aws_access_key("NOTE12345EXAMPLE")
        )
        assert redacted_result["users"][1][0]["credentials"]["token"] == (
            "AWS_ACCESS_KEY_ID=[REDACTED]"
        )
        assert redacted_result["token"] == aws_access_key("ROOT12345EXAMPLE")

    async def test_resource_post_fetch_direct_text_ignores_field_filters(self):
        plugin = SecretsDetectionPlugin(
            make_config(
                field_allowlist=["different.path"],
                field_denylist=["content.text"],
            )
        )
        payload = ResourcePostFetchPayload(
            uri="file:///tmp/secret.txt",
            content=ResourceContent(
                type="resource",
                id="res-1",
                uri="file:///tmp/secret.txt",
                text=aws_access_key("TEST12345EXAMPLE"),
            ),
        )

        result = await plugin.resource_post_fetch(payload, make_context())

        assert result.continue_processing is True
        assert result.violation is None
        assert result.modified_payload is not None
        assert result.modified_payload.content.text == "AWS_ACCESS_KEY_ID=[REDACTED]"
