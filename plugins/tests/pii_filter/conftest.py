import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
PLUGIN_ROOT = REPO_ROOT / "plugins" / "rust" / "python-package" / "pii_filter"

sys.path.insert(0, str(PLUGIN_ROOT))
