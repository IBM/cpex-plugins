# SPDX-License-Identifier: Apache-2.0
"""Build contract tests for plugin-local distribution artifacts."""

from pathlib import Path


def test_build_target_writes_plugin_local_artifacts() -> None:
    # Given the plugin Makefile executed by the CI target.
    makefile_path = Path(__file__).parents[1] / "Makefile"

    # When its build recipe is inspected.
    makefile = makefile_path.read_text()

    # Then uv targets the plugin-local distribution directory.
    assert "uv build --project . --out-dir ./dist" in makefile
