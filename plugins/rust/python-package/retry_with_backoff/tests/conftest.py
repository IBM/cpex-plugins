"""Pytest configuration for retry_with_backoff tests."""

import sys

import mcpgateway_mock
import mcpgateway_mock.common
import mcpgateway_mock.common.models
import mcpgateway_mock.config
import mcpgateway_mock.plugins
import mcpgateway_mock.plugins.framework

sys.modules.setdefault("mcpgateway", mcpgateway_mock)
sys.modules.setdefault("mcpgateway.common", mcpgateway_mock.common)
sys.modules.setdefault("mcpgateway.common.models", mcpgateway_mock.common.models)
sys.modules.setdefault("mcpgateway.config", mcpgateway_mock.config)
sys.modules.setdefault("mcpgateway.plugins", mcpgateway_mock.plugins)
sys.modules.setdefault("mcpgateway.plugins.framework", mcpgateway_mock.plugins.framework)
