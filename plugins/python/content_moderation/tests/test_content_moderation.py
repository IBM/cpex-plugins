"""Unit tests for the content_moderation plugin."""

from __future__ import annotations

import pytest

from cpex_content_moderation.content_moderation import (
    ContentModerationConfig,
    ModerationAction,
    ModerationCategory,
    ModerationProvider,
    ModerationResult,
)


class TestModerationResult:
    """Unit tests for ModerationResult model."""

    def test_creates_valid_result(self):
        """Test that ModerationResult can be created with valid data."""
        result = ModerationResult(
            flagged=True,
            categories={"hate": 0.8, "violence": 0.5},
            action=ModerationAction.BLOCK,
            provider=ModerationProvider.OPENAI,
            confidence=0.85,
        )

        assert result.flagged is True
        assert result.action == ModerationAction.BLOCK
        assert result.confidence == 0.85
        assert result.categories["hate"] == 0.8

    def test_result_with_modified_content(self):
        """Test ModerationResult with modified content."""
        result = ModerationResult(
            flagged=True,
            categories={"profanity": 0.8},
            action=ModerationAction.REDACT,
            provider=ModerationProvider.IBM_WATSON,
            confidence=0.75,
            modified_content="[REDACTED]",
        )

        assert result.modified_content == "[REDACTED]"
        assert result.action == ModerationAction.REDACT

    def test_result_model_dump(self):
        """Test that ModerationResult can be dumped to dict."""
        result = ModerationResult(
            flagged=False,
            categories={"hate": 0.1},
            action=ModerationAction.WARN,
            provider=ModerationProvider.IBM_WATSON,
            confidence=0.1,
            details={"extra": "data"},
        )

        dumped = result.model_dump()

        assert isinstance(dumped, dict)
        assert dumped["flagged"] is False
        assert dumped["confidence"] == 0.1


class TestContentModerationConfig:
    """Unit tests for ContentModerationConfig."""

    def test_default_config_creates_valid_instance(self):
        """Test that default configuration creates valid instance."""
        config = ContentModerationConfig()

        assert config.provider == ModerationProvider.IBM_WATSON
        assert config.enable_caching is True
        assert config.audit_decisions is True
        assert len(config.categories) == 8

    def test_config_with_custom_provider(self):
        """Test configuration with custom provider."""
        config = ContentModerationConfig(provider=ModerationProvider.OPENAI)

        assert config.provider == ModerationProvider.OPENAI

    def test_config_with_custom_categories(self):
        """Test configuration with custom category settings."""
        cfg_data = {
            "categories": {
                "hate": {"threshold": 0.5, "action": "warn"},
                "violence": {"threshold": 0.6, "action": "block"},
            }
        }
        config = ContentModerationConfig(**cfg_data)

        assert config.categories[ModerationCategory.HATE].threshold == 0.5
        assert config.categories[ModerationCategory.VIOLENCE].threshold == 0.6

    def test_config_with_caching_disabled(self):
        """Test configuration with caching disabled."""
        config = ContentModerationConfig(enable_caching=False)

        assert config.enable_caching is False

    def test_config_max_text_length(self):
        """Test configuration max text length setting."""
        config = ContentModerationConfig(max_text_length=5000)

        assert config.max_text_length == 5000

    def test_config_validate_threshold_bounds(self):
        """Test that thresholds are validated as 0-1 range."""
        with pytest.raises(Exception):
            ContentModerationConfig(categories={"hate": {"threshold": 1.5, "action": "block"}})

    def test_config_validate_negative_threshold(self):
        """Test that negative thresholds are rejected."""
        with pytest.raises(Exception):
            ContentModerationConfig(categories={"hate": {"threshold": -0.5, "action": "block"}})


class TestModerationEnums:
    """Unit tests for moderation enum types."""

    def test_moderation_provider_enum_values(self):
        """Test ModerationProvider enum values."""
        assert ModerationProvider.IBM_WATSON.value == "ibm_watson"
        assert ModerationProvider.IBM_GRANITE.value == "ibm_granite"
        assert ModerationProvider.OPENAI.value == "openai"
        assert ModerationProvider.AZURE.value == "azure"
        assert ModerationProvider.AWS.value == "aws"

    def test_moderation_action_enum_values(self):
        """Test ModerationAction enum values."""
        assert ModerationAction.BLOCK.value == "block"
        assert ModerationAction.WARN.value == "warn"
        assert ModerationAction.REDACT.value == "redact"
        assert ModerationAction.TRANSFORM.value == "transform"

    def test_moderation_category_enum_values(self):
        """Test ModerationCategory enum values."""
        assert ModerationCategory.HATE.value == "hate"
        assert ModerationCategory.VIOLENCE.value == "violence"
        assert ModerationCategory.SEXUAL.value == "sexual"
        assert ModerationCategory.SELF_HARM.value == "self_harm"
        assert ModerationCategory.HARASSMENT.value == "harassment"
        assert ModerationCategory.SPAM.value == "spam"
        assert ModerationCategory.PROFANITY.value == "profanity"
        assert ModerationCategory.TOXIC.value == "toxic"

    def test_all_categories_present(self):
        """Test that all expected categories are defined."""
        categories = [cat for cat in ModerationCategory]
        assert len(categories) == 8
