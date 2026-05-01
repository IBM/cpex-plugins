import os
import sys
import types
from pathlib import Path

import plugin_hooks


TESTS_ROOT = Path(__file__).resolve().parent
REPO_ROOT = TESTS_ROOT.parents[1]
PYTHON_PACKAGE_ROOT = REPO_ROOT / "plugins" / "rust" / "python-package"

selected_plugins = set()
for arg in sys.argv[1:]:
    candidate = (Path.cwd() / arg).resolve()
    try:
        relative = candidate.relative_to(TESTS_ROOT)
    except ValueError:
        continue
    if relative.parts:
        selected_plugins.add(relative.parts[0])

if not selected_plugins:
    selected_plugins = {
        path.name
        for path in TESTS_ROOT.iterdir()
        if path.is_dir() and (PYTHON_PACKAGE_ROOT / path.name).exists()
    }

for slug in sorted(selected_plugins):
    plugin_root = PYTHON_PACKAGE_ROOT / slug
    if plugin_root.is_dir() and (plugin_root / "pyproject.toml").exists():
        sys.path.insert(0, str(plugin_root))

if os.environ.get("CPEX_TEST_PLUGIN_HOOKS") != "1":
    raise RuntimeError(
        "Repo-level integration tests require CPEX_TEST_PLUGIN_HOOKS=1; "
        "use the plugin Makefile test targets."
    )

mcpgateway = types.ModuleType("mcpgateway")
common = types.ModuleType("mcpgateway.common")
plugins = types.ModuleType("mcpgateway.plugins")

sys.modules["mcpgateway"] = mcpgateway
sys.modules["mcpgateway.common"] = common
sys.modules["mcpgateway.common.models"] = plugin_hooks
sys.modules["mcpgateway.config"] = plugin_hooks
sys.modules["mcpgateway.plugins"] = plugins
sys.modules["mcpgateway.plugins.framework"] = plugin_hooks
sys.modules["mcpgateway.plugins.framework.models"] = plugin_hooks
