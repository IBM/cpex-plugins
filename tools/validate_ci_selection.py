#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate CI plugin selection payload shape and normalize output."""

from __future__ import annotations

import json
import re
import sys

SLUG_RE = re.compile(r"^[a-z0-9_]+$")


def _assert_slug_list(value: object, field_name: str) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or SLUG_RE.fullmatch(item) is None for item in value
    ):
        raise AssertionError(f"{field_name} must be a slug string list")
    return value


def _assert_mutation_jobs(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise AssertionError("mutation_jobs must be a list")
    for job in value:
        if not isinstance(job, dict):
            raise AssertionError("mutation_jobs entries must be objects")
        cargo_package = job.get("cargo_package")
        in_diff = job.get("in_diff")
        test_packages = job.get("test_packages")
        if not isinstance(cargo_package, str) or SLUG_RE.fullmatch(cargo_package) is None:
            raise AssertionError("mutation_jobs.cargo_package must be a slug")
        if not isinstance(in_diff, bool):
            raise AssertionError("mutation_jobs.in_diff must be bool")
        if not isinstance(test_packages, list) or any(
            not isinstance(item, str) or SLUG_RE.fullmatch(item) is None
            for item in test_packages
        ):
            raise AssertionError("mutation_jobs.test_packages must be a slug string list")
    return value


def main() -> int:
    payload = json.load(sys.stdin)
    plugins = _assert_slug_list(payload.get("plugins"), "plugins")
    cargo_packages = _assert_slug_list(payload.get("cargo_packages"), "cargo_packages")
    mutation_cargo_packages = _assert_slug_list(
        payload.get("mutation_cargo_packages"), "mutation_cargo_packages"
    )
    mutation_jobs = _assert_mutation_jobs(payload.get("mutation_jobs"))
    has_plugins = payload.get("has_plugins")
    plugin_count = payload.get("plugin_count")

    if not isinstance(has_plugins, bool):
        raise AssertionError("has_plugins must be bool")
    if not isinstance(plugin_count, int) or plugin_count != len(plugins):
        raise AssertionError("plugin_count must equal len(plugins)")

    print(
        json.dumps(
            {
                "plugins": plugins,
                "has_plugins": has_plugins,
                "plugin_count": plugin_count,
                "cargo_packages": cargo_packages,
                "mutation_cargo_packages": mutation_cargo_packages,
                "mutation_jobs": mutation_jobs,
                "has_mutation_cargo_packages": bool(mutation_cargo_packages),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
