# SPDX-License-Identifier: Apache-2.0
# Copyright 2024 ContextForge Contributors
"""Tests for Output Length Guard plugin."""

import pytest

from cpex_output_length_guard import OutputLengthGuardConfig, OutputLengthGuardEngine, OutputLengthGuardPlugin


class TestOutputLengthGuardEngine:
    """Tests for OutputLengthGuardEngine."""

    def test_engine_creation(self):
        """Test engine can be created with default config."""
        config = OutputLengthGuardConfig()
        engine = OutputLengthGuardEngine(config.model_dump())
        assert engine is not None

    def test_engine_with_custom_config(self):
        """Test engine can be created with custom config."""
        config = OutputLengthGuardConfig(example_option="custom_value")
        engine = OutputLengthGuardEngine(config.model_dump())
        assert engine is not None



class TestOutputLengthGuardPlugin:
    """Tests for OutputLengthGuardPlugin."""

    def test_plugin_requires_rust_module(self):
        """Test plugin raises error if Rust module not available."""
        # This test assumes the module is installed
        # In a real scenario, you'd mock the import
        pass

    def test_plugin_creation_with_config(self):
        """Test plugin can be created with configuration."""
        # TODO: Create proper plugin config object
        # plugin = OutputLengthGuardPlugin(config)
        # assert plugin is not None
        pass


class TestOutputLengthGuardConfig:
    """Tests for OutputLengthGuardConfig."""

    def test_config_defaults(self):
        """Test configuration has correct defaults."""
        config = OutputLengthGuardConfig()
        assert config.example_option == "default_value"

    def test_config_validation(self):
        """Test configuration validation."""
        config = OutputLengthGuardConfig(example_option="test")
        assert config.example_option == "test"

    def test_config_serialization(self):
        """Test configuration can be serialized."""
        config = OutputLengthGuardConfig(example_option="test")
        data = config.model_dump()
        assert isinstance(data, dict)
        assert data["example_option"] == "test"

    def test_config_deserialization(self):
        """Test configuration can be deserialized from dict."""
        data = {"example_option": "from_dict"}
        config = OutputLengthGuardConfig(**data)
        assert config.example_option == "from_dict"

    def test_config_immutability(self):
        """Test configuration fields are validated on creation."""
        config = OutputLengthGuardConfig(example_option="initial")
        # Pydantic models are mutable by default, but validation occurs
        assert config.example_option == "initial"

    def test_config_with_none_value(self):
        """Test configuration handles None values appropriately."""
        # Depending on field definition, None may or may not be allowed
        config = OutputLengthGuardConfig()
        assert hasattr(config, "example_option")


class TestEdgeCases:
    """Edge case tests for Output Length Guard plugin."""

    def test_config_with_empty_string(self):
        """Test configuration handles empty string values."""
        config = OutputLengthGuardConfig(example_option="")
        assert config.example_option == ""

    def test_config_with_special_characters(self):
        """Test configuration handles special characters."""
        special_value = "test!@#$%^&*()"
        config = OutputLengthGuardConfig(example_option=special_value)
        assert config.example_option == special_value

    def test_engine_with_minimal_config(self):
        """Test engine works with minimal configuration."""
        config = OutputLengthGuardConfig()
        engine = OutputLengthGuardEngine(config.model_dump())
        assert engine is not None

    def test_engine_config_roundtrip(self):
        """Test engine configuration can be serialized and deserialized."""
        config = OutputLengthGuardConfig(example_option="roundtrip_test")
        data = config.model_dump()
        new_config = OutputLengthGuardConfig(**data)
        assert new_config.example_option == config.example_option
