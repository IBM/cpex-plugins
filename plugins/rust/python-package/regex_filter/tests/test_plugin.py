"""Ported regex filter plugin tests for the CPEX package layout."""

from __future__ import annotations

import pytest

from mcpgateway_mock.plugins.framework import (
    GlobalContext,
    Message,
    PluginConfig,
    PluginContext,
    PromptPosthookPayload,
    PromptPrehookPayload,
    PromptResult,
    TextContent,
    ToolPostInvokePayload,
    ToolPreInvokePayload,
)

from cpex_regex_filter.regex_filter import SearchReplacePlugin
from cpex_regex_filter.regex_filter_rust import SearchReplacePluginRust


def _make_config(words=None) -> PluginConfig:
    return PluginConfig(
        name="regex_filter",
        kind="cpex_regex_filter.regex_filter.SearchReplacePlugin",
        version="0.1.0",
        hooks=[
            "prompt_pre_fetch",
            "prompt_post_fetch",
            "tool_pre_invoke",
            "tool_post_invoke",
        ],
        config={"words": words or [{"search": "bad", "replace": "good"}]},
    )


def _make_context() -> PluginContext:
    return PluginContext(global_context=GlobalContext(user="user-1"))


class TestRustEngine:
    def test_simple_replacement(self):
        plugin = SearchReplacePluginRust({"words": [{"search": "bad", "replace": "good"}]})
        assert plugin.apply_patterns("This is bad") == "This is good"

    def test_regex_replacement(self):
        plugin = SearchReplacePluginRust(
            {"words": [{"search": r"\bsecret\b", "replace": "[REDACTED]"}]}
        )
        assert (
            plugin.apply_patterns("The secret password is hidden")
            == "The [REDACTED] password is hidden"
        )

    def test_ssn_replacement(self):
        plugin = SearchReplacePluginRust(
            {"words": [{"search": r"\d{3}-\d{2}-\d{4}", "replace": "XXX-XX-XXXX"}]}
        )
        assert plugin.apply_patterns("SSN: 123-45-6789") == "SSN: XXX-XX-XXXX"

    def test_multiple_replacements(self):
        plugin = SearchReplacePluginRust(
            {
                "words": [
                    {"search": "bad", "replace": "good"},
                    {"search": r"\bsecret\b", "replace": "[REDACTED]"},
                ]
            }
        )
        assert plugin.apply_patterns("This bad secret is bad") == "This good [REDACTED] is good"

    def test_nested_dict(self):
        plugin = SearchReplacePluginRust({"words": [{"search": "bad", "replace": "good"}]})
        modified, new_args = plugin.process_nested({"outer": {"inner": "This is bad"}})
        assert modified is True
        assert new_args["outer"]["inner"] == "This is good"

    def test_list_result(self):
        plugin = SearchReplacePluginRust({"words": [{"search": "bad", "replace": "good"}]})
        modified, new_result = plugin.process_nested(["This is bad", "Another bad thing"])
        assert modified is True
        assert new_result == ["This is good", "Another good thing"]

    def test_chained_replacements(self):
        plugin = SearchReplacePluginRust(
            {
                "words": [
                    {"search": "foo", "replace": "bar"},
                    {"search": "bar", "replace": "baz"},
                ]
            }
        )
        assert plugin.apply_patterns("foo") == "baz"

    def test_empty_string_input(self):
        plugin = SearchReplacePluginRust({"words": [{"search": "test", "replace": "TEST"}]})
        modified, result = plugin.process_nested("")
        assert modified is False
        assert result == ""

    def test_unicode_emojis(self):
        plugin = SearchReplacePluginRust({"words": [{"search": "bad", "replace": "good"}]})
        modified, result = plugin.process_nested("This is bad 😀 very bad 🎉")
        assert modified is True
        assert result == "This is good 😀 very good 🎉"

    def test_dict_with_none_values(self):
        plugin = SearchReplacePluginRust({"words": [{"search": "bad", "replace": "good"}]})
        modified, result = plugin.process_nested({"key1": "bad", "key2": None})
        assert modified is True
        assert result["key1"] == "good"
        assert result["key2"] is None

    def test_list_with_mixed_types(self):
        plugin = SearchReplacePluginRust({"words": [{"search": "bad", "replace": "good"}]})
        modified, result = plugin.process_nested(["bad", 123, None, {"nested": "bad"}])
        assert modified is True
        assert result == ["good", 123, None, {"nested": "good"}]

    def test_character_class(self):
        plugin = SearchReplacePluginRust({"words": [{"search": r"[0-9]+", "replace": "NUM"}]})
        assert plugin.apply_patterns("I have 123 apples and 456 oranges") == "I have NUM apples and NUM oranges"

    def test_word_boundary_pattern(self):
        plugin = SearchReplacePluginRust({"words": [{"search": r"\bcat\b", "replace": "dog"}]})
        assert plugin.apply_patterns("The cat and the caterpillar") == "The dog and the caterpillar"

    def test_case_insensitive_pattern(self):
        plugin = SearchReplacePluginRust({"words": [{"search": r"(?i)test", "replace": "EXAM"}]})
        assert plugin.apply_patterns("Test TEST test TeSt") == "EXAM EXAM EXAM EXAM"

    def test_email_redaction(self):
        plugin = SearchReplacePluginRust(
            {
                "words": [
                    {
                        "search": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                        "replace": "[EMAIL]",
                    }
                ]
            }
        )
        assert (
            plugin.apply_patterns("Contact me at john.doe@example.com or jane@test.org")
            == "Contact me at [EMAIL] or [EMAIL]"
        )

    def test_credit_card_redaction(self):
        plugin = SearchReplacePluginRust(
            {"words": [{"search": r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", "replace": "[CARD]"}]}
        )
        assert plugin.apply_patterns("Card: 1234-5678-9012-3456 or 1234567890123456") == "Card: [CARD] or [CARD]"

    def test_ipv4_address_redaction(self):
        plugin = SearchReplacePluginRust(
            {"words": [{"search": r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "replace": "[IP]"}]}
        )
        assert plugin.apply_patterns("Server at 192.168.1.1 and 10.0.0.1") == "Server at [IP] and [IP]"

    def test_url_redaction(self):
        plugin = SearchReplacePluginRust({"words": [{"search": r"https?://[^\s]+", "replace": "[URL]"}]})
        assert plugin.apply_patterns("Visit https://example.com or http://test.org/path") == "Visit [URL] or [URL]"

    def test_empty_config_no_words(self):
        plugin = SearchReplacePluginRust({"words": []})
        assert plugin.apply_patterns("clean") == "clean"

    def test_invalid_regex_detected(self):
        with pytest.raises(ValueError, match="Invalid regex patterns detected"):
            SearchReplacePluginRust({"words": [{"search": "[invalid(", "replace": "test"}]})

    def test_missing_search_field(self):
        with pytest.raises(ValueError, match="Missing 'search' field"):
            SearchReplacePluginRust({"words": [{"replace": "test"}]})

    def test_missing_replace_field(self):
        with pytest.raises(ValueError, match="Missing 'replace' field"):
            SearchReplacePluginRust({"words": [{"search": "test"}]})


class TestPluginHooks:
    @pytest.fixture
    def plugin(self):
        return SearchReplacePlugin(_make_config())

    async def test_prompt_pre_fetch_simple_replacement(self, plugin):
        payload = PromptPrehookPayload(prompt_id="prompt-1", args={"message": "This is bad"})
        result = await plugin.prompt_pre_fetch(payload, _make_context())
        assert result.modified_payload is not None
        assert result.modified_payload.args["message"] == "This is good"

    async def test_prompt_pre_fetch_no_change_returns_default_result(self, plugin):
        payload = PromptPrehookPayload(prompt_id="prompt-1", args={"message": "This is fine"})
        result = await plugin.prompt_pre_fetch(payload, _make_context())
        assert result.modified_payload is None
        assert result.continue_processing is True

    async def test_prompt_post_fetch_message_replacement(self, plugin):
        payload = PromptPosthookPayload(
            result=PromptResult(
                messages=[Message(role="assistant", content=TextContent(text="This is bad"))]
            )
        )
        result = await plugin.prompt_post_fetch(payload, _make_context())
        assert result.modified_payload is not None
        assert result.modified_payload.result.messages[0].content.text == "This is good"

    async def test_tool_pre_invoke_nested_dict(self, plugin):
        payload = ToolPreInvokePayload(name="search", args={"outer": {"inner": "bad"}})
        result = await plugin.tool_pre_invoke(payload, _make_context())
        assert result.modified_payload is not None
        assert result.modified_payload.args["outer"]["inner"] == "good"

    async def test_tool_post_invoke_list_result(self, plugin):
        payload = ToolPostInvokePayload(name="search", result=["bad", "still bad"])
        result = await plugin.tool_post_invoke(payload, _make_context())
        assert result.modified_payload is not None
        assert result.modified_payload.result == ["good", "still good"]

    async def test_none_args_are_left_untouched(self, plugin):
        payload = PromptPrehookPayload(prompt_id="prompt-1", args=None)
        result = await plugin.prompt_pre_fetch(payload, _make_context())
        assert result.modified_payload is None
