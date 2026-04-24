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

    def test_tuple_result(self):
        plugin = SearchReplacePluginRust({"words": [{"search": "bad", "replace": "good"}]})
        modified, new_result = plugin.process_nested(("bad", {"nested": "bad"}))
        assert modified is True
        assert new_result == ("good", {"nested": "good"})

    def test_cyclic_list_does_not_recurse_forever(self):
        plugin = SearchReplacePluginRust({"words": [{"search": "bad", "replace": "good"}]})
        data = []
        data.append(data)
        with pytest.raises(ValueError, match="Cyclic containers are not supported"):
            plugin.process_nested(data)

    def test_cyclic_list_with_modified_sibling_raises(self):
        plugin = SearchReplacePluginRust({"words": [{"search": "bad", "replace": "good"}]})
        data = ["bad"]
        data.append(data)
        with pytest.raises(ValueError, match="Cyclic containers are not supported"):
            plugin.process_nested(data)

    def test_mixed_dict_list_cycle_raises(self):
        plugin = SearchReplacePluginRust({"words": [{"search": "bad", "replace": "good"}]})
        data = {"items": ["bad"]}
        data["items"].append(data)
        with pytest.raises(ValueError, match="Cyclic containers are not supported"):
            plugin.process_nested(data)

    def test_deeply_nested_values_stop_at_depth_limit(self):
        plugin = SearchReplacePluginRust({"words": [{"search": "bad", "replace": "good"}]})
        data = "bad"
        for _ in range(70):
            data = [data]
        with pytest.raises(ValueError, match="Maximum nested depth"):
            plugin.process_nested(data)

    def test_large_text_still_filters(self):
        plugin = SearchReplacePluginRust(
            {"words": [{"search": "bad", "replace": "good"}], "max_text_bytes": 1024}
        )
        text = "bad" * 100
        modified, new_result = plugin.process_nested(text)
        assert modified is True
        assert new_result == "good" * 100

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

    @pytest.mark.parametrize(
        ("replace", "expected"),
        [
            ("$0", "ab"),
            ("$1", "a"),
            ("$10", ""),
            ("$1_a", ""),
            ("$1.a", "a.a"),
            ("$word.ext", "b.ext"),
            ("${word}", "b"),
            ("${word.ext}", ""),
            ("$$", "$"),
            ("$", "$"),
            ("${word", "${word"),
            ("[$missing]", "[]"),
        ],
    )
    def test_replacement_syntax_matches_rust_regex(self, replace, expected):
        plugin = SearchReplacePluginRust(
            {"words": [{"search": r"(a)(?P<word>b)?", "replace": replace}]}
        )
        assert plugin.apply_patterns("ab") == expected

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

    def test_words_must_be_a_list(self):
        with pytest.raises(ValueError, match="'words' must be a list"):
            SearchReplacePluginRust({"words": {"search": "bad", "replace": "good"}})

    def test_text_limit_rejects_oversized_payload(self):
        plugin = SearchReplacePluginRust(
            {"words": [{"search": "bad", "replace": "good"}], "max_text_bytes": 2}
        )
        with pytest.raises(ValueError, match="Text exceeds max_text_bytes"):
            plugin.process_nested("bad")

    def test_apply_patterns_enforces_text_limit(self):
        plugin = SearchReplacePluginRust(
            {"words": [{"search": "bad", "replace": "good"}], "max_text_bytes": 2}
        )
        with pytest.raises(ValueError, match="Text exceeds max_text_bytes"):
            plugin.apply_patterns("bad")

    def test_output_limit_rejects_expanding_replacement(self):
        plugin = SearchReplacePluginRust(
            {
                "words": [{"search": "a", "replace": "bbbb"}],
                "max_text_bytes": 16,
                "max_output_bytes": 3,
            }
        )
        with pytest.raises(ValueError, match="Output exceeds max_output_bytes"):
            plugin.apply_patterns("a")

    def test_output_limit_stops_before_huge_replacement_finishes(self):
        plugin = SearchReplacePluginRust(
            {
                "words": [{"search": "a", "replace": "bbbb"}],
                "max_text_bytes": 16,
                "max_output_bytes": 12,
            }
        )
        with pytest.raises(ValueError, match="Output exceeds max_output_bytes"):
            plugin.apply_patterns("aaaa")

    def test_output_limit_bounds_capture_expansion(self):
        plugin = SearchReplacePluginRust(
            {
                "words": [{"search": r"(a+)", "replace": "$1$1$1"}],
                "max_text_bytes": 16,
                "max_output_bytes": 5,
            }
        )
        with pytest.raises(ValueError, match="Output exceeds max_output_bytes"):
            plugin.apply_patterns("aa")

    def test_pattern_limit_rejects_oversized_config(self):
        with pytest.raises(ValueError, match="'words' contains 2 patterns, maximum is 1"):
            SearchReplacePluginRust(
                {
                    "words": [
                        {"search": "bad", "replace": "good"},
                        {"search": "secret", "replace": "safe"},
                    ],
                    "max_patterns": 1,
                }
            )

    def test_replacement_limit_rejects_oversized_config(self):
        with pytest.raises(ValueError, match="replacement exceeds max_replace_bytes"):
            SearchReplacePluginRust(
                {
                    "words": [{"search": "bad", "replace": "good"}],
                    "max_replace_bytes": 2,
                }
            )

    def test_search_limit_rejects_oversized_config(self):
        with pytest.raises(ValueError, match="search exceeds max_search_bytes"):
            SearchReplacePluginRust(
                {
                    "words": [{"search": "bad", "replace": "good"}],
                    "max_search_bytes": 2,
                }
            )

    def test_collection_limit_rejects_oversized_payload(self):
        plugin = SearchReplacePluginRust(
            {"words": [{"search": "bad", "replace": "good"}], "max_collection_items": 1}
        )
        with pytest.raises(ValueError, match="Collection exceeds max_collection_items"):
            plugin.process_nested(["bad", "bad"])

    def test_total_item_limit_rejects_oversized_traversal(self):
        plugin = SearchReplacePluginRust(
            {"words": [{"search": "bad", "replace": "good"}], "max_total_items": 2}
        )
        with pytest.raises(ValueError, match="Traversal exceeds max_total_items"):
            plugin.process_nested([["bad"], ["bad"]])

    def test_nested_output_limit_is_aggregate(self):
        plugin = SearchReplacePluginRust(
            {
                "words": [{"search": "a", "replace": "bbb"}],
                "max_text_bytes": 16,
                "max_output_bytes": 5,
            }
        )
        with pytest.raises(ValueError, match="Output exceeds max_output_bytes"):
            plugin.process_nested(["a", "a"])

    def test_nested_output_limit_counts_unchanged_strings(self):
        plugin = SearchReplacePluginRust(
            {
                "words": [{"search": "missing", "replace": "found"}],
                "max_text_bytes": 16,
                "max_output_bytes": 5,
            }
        )
        with pytest.raises(ValueError, match="Output exceeds max_output_bytes"):
            plugin.process_nested(["aaa", "aaa"])

    def test_nested_input_limit_is_aggregate(self):
        plugin = SearchReplacePluginRust(
            {
                "words": [{"search": "missing", "replace": "found"}],
                "max_text_bytes": 16,
                "max_total_text_bytes": 5,
            }
        )
        with pytest.raises(ValueError, match="Input exceeds max_total_text_bytes"):
            plugin.process_nested(["aaa", "aaa"])

    def test_custom_objects_are_left_unchanged(self):
        class CustomValue:
            text = "bad"

        plugin = SearchReplacePluginRust({"words": [{"search": "bad", "replace": "good"}]})
        value = CustomValue()
        modified, result = plugin.process_nested(value)
        assert modified is False
        assert result is value

    def test_depth_limit_boundary(self):
        plugin = SearchReplacePluginRust(
            {"words": [{"search": "bad", "replace": "good"}], "max_nested_depth": 2}
        )
        modified, result = plugin.process_nested(["bad"])
        assert modified is True
        assert result == ["good"]
        with pytest.raises(ValueError, match="Maximum nested depth"):
            plugin.process_nested([["bad"]])

    def test_set_result(self):
        plugin = SearchReplacePluginRust({"words": [{"search": "bad", "replace": "good"}]})
        modified, new_result = plugin.process_nested({"bad", "fine"})
        assert modified is True
        assert new_result == {"good", "fine"}


class TestPluginHooks:
    @pytest.fixture
    def plugin(self):
        return SearchReplacePlugin(_make_config())

    class ModelCopyPayload:
        def __init__(self, **attrs):
            self.__dict__.update(attrs)

        def model_copy(self, *, update=None):
            attrs = dict(self.__dict__)
            if update:
                attrs.update(update)
            return TestPluginHooks.ModelCopyPayload(**attrs)

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
        original_content = TextContent(text="This is bad")
        original_message = Message(role="assistant", content=original_content)
        payload = PromptPosthookPayload(
            result=PromptResult(messages=[original_message])
        )
        result = await plugin.prompt_post_fetch(payload, _make_context())
        assert result.modified_payload is not None
        assert result.modified_payload.result.messages[0].content.text == "This is good"
        assert payload.result.messages[0].content.text == "This is bad"
        assert result.modified_payload is not payload
        assert result.modified_payload.result is not payload.result
        assert result.modified_payload.result.messages[0] is not original_message
        assert result.modified_payload.result.messages[0].content is not original_content

    async def test_prompt_post_fetch_uses_model_copy_path(self, plugin):
        original_content = self.ModelCopyPayload(text="This is bad")
        original_message = self.ModelCopyPayload(role="assistant", content=original_content)
        original_result = self.ModelCopyPayload(messages=[original_message])
        payload = self.ModelCopyPayload(result=original_result)

        result = await plugin.prompt_post_fetch(payload, _make_context())

        assert result.modified_payload is not None
        assert result.modified_payload.result.messages[0].content.text == "This is good"
        assert payload.result.messages[0].content.text == "This is bad"
        assert result.modified_payload is not payload
        assert result.modified_payload.result is not original_result
        assert result.modified_payload.result.messages[0] is not original_message
        assert result.modified_payload.result.messages[0].content is not original_content

    async def test_prompt_post_fetch_error_does_not_partially_mutate(self):
        plugin = SearchReplacePlugin(
            PluginConfig(
                name="regex_filter",
                kind="cpex_regex_filter.regex_filter.SearchReplacePlugin",
                version="0.1.0",
                hooks=["prompt_post_fetch"],
                config={
                    "words": [{"search": "bad", "replace": "good"}],
                    "max_text_bytes": 4,
                },
            )
        )
        payload = PromptPosthookPayload(
            result=PromptResult(
                messages=[
                    Message(role="assistant", content=TextContent(text="bad")),
                    Message(role="assistant", content=TextContent(text="too long")),
                ]
            )
        )
        with pytest.raises(ValueError, match="Text exceeds max_text_bytes"):
            await plugin.prompt_post_fetch(payload, _make_context())
        assert payload.result.messages[0].content.text == "bad"
        assert payload.result.messages[1].content.text == "too long"

    async def test_prompt_post_fetch_model_copy_error_does_not_partially_mutate(self):
        plugin = SearchReplacePlugin(
            PluginConfig(
                name="regex_filter",
                kind="cpex_regex_filter.regex_filter.SearchReplacePlugin",
                version="0.1.0",
                hooks=["prompt_post_fetch"],
                config={
                    "words": [{"search": "bad", "replace": "good"}],
                    "max_text_bytes": 4,
                },
            )
        )
        payload = self.ModelCopyPayload(
            result=self.ModelCopyPayload(
                messages=[
                    self.ModelCopyPayload(
                        role="assistant", content=self.ModelCopyPayload(text="bad")
                    ),
                    self.ModelCopyPayload(
                        role="assistant", content=self.ModelCopyPayload(text="too long")
                    ),
                ]
            )
        )

        with pytest.raises(ValueError, match="Text exceeds max_text_bytes"):
            await plugin.prompt_post_fetch(payload, _make_context())
        assert payload.result.messages[0].content.text == "bad"
        assert payload.result.messages[1].content.text == "too long"

    async def test_prompt_post_fetch_enforces_message_count_limit(self):
        plugin = SearchReplacePlugin(
            PluginConfig(
                name="regex_filter",
                kind="cpex_regex_filter.regex_filter.SearchReplacePlugin",
                version="0.1.0",
                hooks=["prompt_post_fetch"],
                config={
                    "words": [{"search": "bad", "replace": "good"}],
                    "max_collection_items": 1,
                },
            )
        )
        payload = PromptPosthookPayload(
            result=PromptResult(
                messages=[
                    Message(role="assistant", content=TextContent(text="bad")),
                    Message(role="assistant", content=TextContent(text="bad")),
                ]
            )
        )
        with pytest.raises(ValueError, match="Collection exceeds max_collection_items"):
            await plugin.prompt_post_fetch(payload, _make_context())

    async def test_prompt_post_fetch_enforces_total_item_limit(self):
        plugin = SearchReplacePlugin(
            PluginConfig(
                name="regex_filter",
                kind="cpex_regex_filter.regex_filter.SearchReplacePlugin",
                version="0.1.0",
                hooks=["prompt_post_fetch"],
                config={
                    "words": [{"search": "bad", "replace": "good"}],
                    "max_total_items": 1,
                },
            )
        )
        payload = PromptPosthookPayload(
            result=PromptResult(
                messages=[
                    Message(role="assistant", content=TextContent(text="bad")),
                    Message(role="assistant", content=TextContent(text="bad")),
                ]
            )
        )
        with pytest.raises(ValueError, match="Traversal exceeds max_total_items"):
            await plugin.prompt_post_fetch(payload, _make_context())

    async def test_prompt_post_fetch_enforces_aggregate_input_limit(self):
        plugin = SearchReplacePlugin(
            PluginConfig(
                name="regex_filter",
                kind="cpex_regex_filter.regex_filter.SearchReplacePlugin",
                version="0.1.0",
                hooks=["prompt_post_fetch"],
                config={
                    "words": [{"search": "missing", "replace": "found"}],
                    "max_text_bytes": 16,
                    "max_total_text_bytes": 5,
                },
            )
        )
        payload = PromptPosthookPayload(
            result=PromptResult(
                messages=[
                    Message(role="assistant", content=TextContent(text="aaa")),
                    Message(role="assistant", content=TextContent(text="aaa")),
                ]
            )
        )
        with pytest.raises(ValueError, match="Input exceeds max_total_text_bytes"):
            await plugin.prompt_post_fetch(payload, _make_context())

    async def test_prompt_post_fetch_enforces_aggregate_output_limit(self):
        plugin = SearchReplacePlugin(
            PluginConfig(
                name="regex_filter",
                kind="cpex_regex_filter.regex_filter.SearchReplacePlugin",
                version="0.1.0",
                hooks=["prompt_post_fetch"],
                config={
                    "words": [{"search": "bad", "replace": "good"}],
                    "max_output_bytes": 7,
                },
            )
        )
        payload = PromptPosthookPayload(
            result=PromptResult(
                messages=[
                    Message(role="assistant", content=TextContent(text="bad")),
                    Message(role="assistant", content=TextContent(text="bad")),
                ]
            )
        )
        with pytest.raises(ValueError, match="Output exceeds max_output_bytes"):
            await plugin.prompt_post_fetch(payload, _make_context())

    async def test_prompt_post_fetch_output_limit_counts_unchanged_messages(self):
        plugin = SearchReplacePlugin(
            PluginConfig(
                name="regex_filter",
                kind="cpex_regex_filter.regex_filter.SearchReplacePlugin",
                version="0.1.0",
                hooks=["prompt_post_fetch"],
                config={
                    "words": [{"search": "missing", "replace": "found"}],
                    "max_output_bytes": 5,
                },
            )
        )
        payload = PromptPosthookPayload(
            result=PromptResult(
                messages=[
                    Message(role="assistant", content=TextContent(text="aaa")),
                    Message(role="assistant", content=TextContent(text="aaa")),
                ]
            )
        )
        with pytest.raises(ValueError, match="Output exceeds max_output_bytes"):
            await plugin.prompt_post_fetch(payload, _make_context())

    async def test_prompt_post_fetch_no_change_returns_default_result(self, plugin):
        payload = PromptPosthookPayload(
            result=PromptResult(
                messages=[Message(role="assistant", content=TextContent(text="This is fine"))]
            )
        )
        result = await plugin.prompt_post_fetch(payload, _make_context())
        assert result.modified_payload is None
        assert result.continue_processing is True

    async def test_prompt_post_fetch_ignores_messages_without_text(self, plugin):
        class BadContent:
            pass

        class BadMessage:
            role = "assistant"
            content = BadContent()

        payload = PromptPosthookPayload(result=PromptResult(messages=[BadMessage()]))
        result = await plugin.prompt_post_fetch(payload, _make_context())
        assert result.modified_payload is None

    async def test_prompt_post_fetch_non_list_messages_returns_default_result(self, plugin):
        class BadResult:
            messages = "not-a-list"

        payload = PromptPosthookPayload(result=BadResult())
        result = await plugin.prompt_post_fetch(payload, _make_context())
        assert result.modified_payload is None

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
