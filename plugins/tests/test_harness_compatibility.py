# SPDX-License-Identifier: Apache-2.0
"""Compatibility tests for the repository integration-test harness."""

from __future__ import annotations

import dataclasses
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable

import pytest

import plugin_hooks


REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = Path(__file__).resolve().parent
UserContext = dataclasses.make_dataclass("UserContext", [("email", str)])


def _run_harness(script: str, *, cwd: Path = REPO_ROOT) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["CPEX_TEST_PLUGIN_HOOKS"] = "1"
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_fallback_prefers_python_package_root_when_both_roots_match(tmp_path: Path) -> None:
    # Given a copied harness and the same plugin slug under both package roots.
    tests_root = tmp_path / "plugins" / "tests"
    tests_root.mkdir(parents=True)
    shutil.copy2(TESTS_ROOT / "conftest.py", tests_root / "conftest.py")
    shutil.copy2(TESTS_ROOT / "plugin_hooks.py", tests_root / "plugin_hooks.py")
    (tests_root / "dual_root").mkdir()
    for package_root in (
        tmp_path / "plugins" / "python",
        tmp_path / "plugins" / "rust" / "python-package",
    ):
        plugin_root = package_root / "dual_root"
        (plugin_root / "cpex_dual_root").mkdir(parents=True)
        (plugin_root / "pyproject.toml").touch()

    script = f"""
import sys
from pathlib import Path
sys.argv = ["pytest"]
sys.path.insert(0, {str(tests_root)!r})
import conftest
expected = [
    Path({str(tmp_path / "plugins" / "python")!r}),
    Path({str(tmp_path / "plugins" / "rust" / "python-package")!r}),
]
assert conftest.PYTHON_PACKAGE_ROOTS == expected
assert Path(sys.path[0]) == expected[0] / "dual_root"
"""

    # When the copied conftest performs no-argument fallback discovery.
    result = _run_harness(script, cwd=tmp_path)

    # Then Python is searched first and its matching package root is selected.
    assert result.returncode == 0, result.stderr


def test_python_plugin_imports_through_constants_shim() -> None:
    # Given pytest selection of the pure-Python ICA plugin.
    script = f"""
import sys
from pathlib import Path
sys.argv = ["pytest", {str(TESTS_ROOT / "ica_metering_exporter" / "test_integration.py")!r}]
sys.path.insert(0, {str(TESTS_ROOT)!r})
import conftest
import cpex.framework.constants as constants_module
from cpex.framework.constants import GATEWAY_METADATA
import cpex_ica_metering_exporter
assert GATEWAY_METADATA == "gateway"
assert constants_module is conftest.constants_mod
assert constants_module is not conftest.real_constants
assert Path(sys.path[0]) == Path({str(REPO_ROOT / "plugins" / "python" / "ica_metering_exporter")!r})
"""

    # When conftest installs its framework shims in a fresh process.
    result = _run_harness(script)

    # Then constants remains importable and the selected plugin imports cleanly.
    assert result.returncode == 0, result.stderr


def test_context_fields_are_defaulted_and_isolated() -> None:
    # Given two independently constructed shim contexts.
    first_global = plugin_hooks.GlobalContext()
    second_global = plugin_hooks.GlobalContext()
    first_plugin = plugin_hooks.PluginContext()
    second_plugin = plugin_hooks.PluginContext()

    # When one context's state and metadata are mutated.
    first_global.state["global"] = 1
    first_global.metadata["metadata"] = 2
    first_plugin.state["plugin"] = 3

    # Then defaults exist and no mutable value is shared.
    assert first_global.user_context is None
    assert second_global.state == {}
    assert second_global.metadata == {}
    assert second_plugin.state == {}


@pytest.mark.parametrize(
    ("global_context_factory", "expected"),
    [
        (
            lambda: plugin_hooks.GlobalContext(
                user_context=UserContext(email="structured@example.test"),
                user="legacy@example.test",
            ),
            "structured@example.test",
        ),
        (
            lambda: plugin_hooks.GlobalContext(user="string@example.test"),
            "string@example.test",
        ),
        (
            lambda: plugin_hooks.GlobalContext(
                user={"email": "dict@example.test"},
            ),
            "dict@example.test",
        ),
        (
            lambda: plugin_hooks.GlobalContext(
                user={"name": "anonymous"},
            ),
            None,
        ),
    ],
)
def test_user_email_matches_framework_fallbacks(
    global_context_factory: Callable[[], plugin_hooks.GlobalContext],
    expected: str | None,
) -> None:
    # Given each supported global user representation.
    context = plugin_hooks.PluginContext(global_context=global_context_factory())

    # When the shim resolves the user's email.
    actual = context.user_email

    # Then structured, string, dict, and absent values match framework behavior.
    assert actual == expected


@pytest.mark.parametrize(
    ("slug", "selected_path"),
    [
        ("ica_metering_exporter", "plugins/python/ica_metering_exporter"),
        ("rate_limiter", "plugins/rust/python-package/rate_limiter"),
    ],
)
def test_plugin_test_dry_run_selects_existing_language_root(slug: str, selected_path: str) -> None:
    # Given a real plugin slug from either supported language root.
    # When root Make routing is evaluated without executing sync or CI.
    result = subprocess.run(
        ["make", "-n", "plugin-test", f"PLUGIN={slug}"],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    # Then the command selects exactly the plugin's existing directory.
    assert result.returncode == 0, result.stderr
    assert f"cd {selected_path} && make sync && make ci" in result.stdout


@pytest.mark.parametrize("slug", ["nonexistent_plugin", "../tests"])
def test_plugin_test_rejects_unknown_or_malformed_slug_before_sync(slug: str) -> None:
    # Given an unknown or path-traversing plugin slug.
    # When the root plugin-test target is invoked.
    result = subprocess.run(
        ["make", "plugin-test", f"PLUGIN={slug}"],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    # Then routing fails with the stable unknown-plugin message before sync.
    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert f"Unknown plugin {slug}" in output
    assert "uv sync" not in output
