"""Pytest configuration — inject mcpgateway mock before any plugin imports."""

import sys

import mcpgateway_mock
import mcpgateway_mock.plugins
import mcpgateway_mock.plugins.framework

# Alias the mock package tree into sys.modules under the real names.
sys.modules.setdefault("mcpgateway", mcpgateway_mock)
sys.modules.setdefault("mcpgateway.plugins", mcpgateway_mock.plugins)
sys.modules.setdefault("mcpgateway.plugins.framework", mcpgateway_mock.plugins.framework)
