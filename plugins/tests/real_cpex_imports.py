"""Helpers for subprocess import checks against the real cpex package."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path


def assert_real_cpex_imports(plugin_root: Path, import_statements: list[str]) -> None:
    script = "\n".join(
        [
            "import importlib",
            "for name in ('cpex', 'cpex.framework', 'cpex.framework.models', 'cpex.framework.settings'):",
            "    importlib.import_module(name)",
            *import_statements,
            "print('ok')",
        ]
    )
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    result = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(script)],
        cwd=plugin_root if plugin_root.exists() else None,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"
