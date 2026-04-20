import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
PLUGIN_ROOT = REPO_ROOT / "plugins" / "rust" / "python-package" / "pii_filter"

sys.path.insert(0, str(HERE))
sys.path.insert(0, str(PLUGIN_ROOT))

import mcpgateway_mock
import mcpgateway_mock.plugins
import mcpgateway_mock.plugins.framework


sys.modules.setdefault("mcpgateway", mcpgateway_mock)
sys.modules.setdefault("mcpgateway.plugins", mcpgateway_mock.plugins)
sys.modules.setdefault("mcpgateway.plugins.framework", mcpgateway_mock.plugins.framework)
