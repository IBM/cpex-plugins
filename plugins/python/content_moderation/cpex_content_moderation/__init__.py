# -*- coding: utf-8 -*-
"""Content Moderation Plugin for ContextForge.

This package provides advanced content moderation capabilities using multiple
AI providers including IBM Watson, IBM Granite Guardian, OpenAI, Azure, and AWS.
"""

# Mock mcpgateway if not available (for standalone unit testing)
import sys
from unittest.mock import MagicMock

if "mcpgateway" not in sys.modules:
    sys.modules["mcpgateway"] = MagicMock()
    sys.modules["mcpgateway.config"] = MagicMock()
    sys.modules["mcpgateway.plugins"] = MagicMock()
    sys.modules["mcpgateway.plugins.framework"] = MagicMock()

from .content_moderation import ContentModerationPlugin

__version__ = "1.0.0"
__all__ = ["ContentModerationPlugin"]
