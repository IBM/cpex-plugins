import sys
from pathlib import Path


TESTS_ROOT = Path(__file__).resolve().parent
REPO_ROOT = TESTS_ROOT.parents[1]
PYTHON_PACKAGE_ROOT = REPO_ROOT / "plugins" / "rust" / "python-package"

for plugin_root in sorted(PYTHON_PACKAGE_ROOT.iterdir()):
    if plugin_root.is_dir() and (plugin_root / "pyproject.toml").exists():
        sys.path.insert(0, str(plugin_root))
