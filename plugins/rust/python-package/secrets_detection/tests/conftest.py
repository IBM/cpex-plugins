import sys

import mcpgateway_mock
import mcpgateway_mock.plugins
import mcpgateway_mock.plugins.framework

sys.modules.setdefault("mcpgateway", mcpgateway_mock)
sys.modules.setdefault("mcpgateway.plugins", mcpgateway_mock.plugins)
sys.modules.setdefault("mcpgateway.plugins.framework", mcpgateway_mock.plugins.framework)
