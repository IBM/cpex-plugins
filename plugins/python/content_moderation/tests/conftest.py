"""Pytest configuration for content_moderation unit tests.

Mock mcpgateway before any imports that depend on it.
"""

import sys
from unittest.mock import MagicMock

sys.modules["mcpgateway"] = MagicMock()
sys.modules["mcpgateway.config"] = MagicMock()
sys.modules["mcpgateway.plugins"] = MagicMock()
sys.modules["mcpgateway.plugins.framework"] = MagicMock()
