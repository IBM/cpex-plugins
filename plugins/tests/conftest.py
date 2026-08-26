import os
import sys
import types
from pathlib import Path

import plugin_hooks


TESTS_ROOT = Path(__file__).resolve().parent
REPO_ROOT = TESTS_ROOT.parents[1]
PYTHON_PACKAGE_ROOTS = [
    REPO_ROOT / "plugins" / "python",
    REPO_ROOT / "plugins" / "rust" / "python-package",
]

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
        if path.is_dir()
        and any((package_root / path.name).exists() for package_root in PYTHON_PACKAGE_ROOTS)
    }

for slug in sorted(selected_plugins):
    for package_root in PYTHON_PACKAGE_ROOTS:
        plugin_root = package_root / slug
        if (
            plugin_root.is_dir()
            and (plugin_root / "pyproject.toml").exists()
            and (plugin_root / f"cpex_{slug}").is_dir()
        ):
            sys.path.insert(0, str(plugin_root))
            break

if os.environ.get("CPEX_TEST_PLUGIN_HOOKS") != "1":
    raise RuntimeError(
        "Repo-level integration tests require CPEX_TEST_PLUGIN_HOOKS=1; "
        "use the plugin Makefile test targets."
    )

# Import real extensions module from cpex (needed for extensions tests)
try:
    from cpex.framework import extensions as real_extensions
except ImportError:
    real_extensions = None

try:
    from cpex.framework import constants as real_constants
except ImportError:
    real_constants = None

cpex = types.ModuleType("cpex")
framework = types.ModuleType("cpex.framework")
hooks = types.ModuleType("cpex.framework.hooks")
policies = types.ModuleType("cpex.framework.hooks.policies")
memory = types.ModuleType("cpex.framework.memory")
extensions_mod = types.ModuleType("cpex.framework.extensions") if real_extensions else None
constants_mod = types.ModuleType("cpex.framework.constants") if real_constants else None

framework.__dict__.update(plugin_hooks.__dict__)
policies.HookPayloadPolicy = plugin_hooks.HookPayloadPolicy
policies.apply_policy = plugin_hooks.apply_policy
memory.wrap_payload_for_isolation = plugin_hooks.wrap_payload_for_isolation
if real_extensions and extensions_mod:
    extensions_mod.__dict__.update(real_extensions.__dict__)
if real_constants and constants_mod:
    constants_mod.__dict__.update(real_constants.__dict__)
    framework.constants = constants_mod

sys.modules["cpex"] = cpex
sys.modules["cpex.framework"] = framework
sys.modules["cpex.framework.hooks"] = hooks
sys.modules["cpex.framework.hooks.policies"] = policies
sys.modules["cpex.framework.memory"] = memory
sys.modules["cpex.framework.models"] = plugin_hooks
sys.modules["cpex.framework.settings"] = plugin_hooks
if extensions_mod:
    sys.modules["cpex.framework.extensions"] = extensions_mod
if constants_mod:
    sys.modules["cpex.framework.constants"] = constants_mod
