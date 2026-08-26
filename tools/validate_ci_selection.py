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


def _assert_string_list(value: object, field_name: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise AssertionError(f"{field_name} must be a string list")
    return value


def _assert_bool(value: object, field_name: str, expected: bool) -> bool:
    if not isinstance(value, bool):
        raise AssertionError(f"{field_name} must be bool")
    if value is not expected:
        raise AssertionError(f"{field_name} must match its list")
    return value


def _assert_count(value: object, field_name: str, items: list[str]) -> int:
    if type(value) is not int or value != len(items):
        raise AssertionError(f"{field_name} must equal len of its plugin list")
    return value


def main() -> int:
    payload = json.load(sys.stdin)
    if not isinstance(payload, dict):
        raise AssertionError("CI selection payload must be an object")
    plugins = _assert_slug_list(payload.get("plugins"), "plugins")
    rust_plugins = _assert_slug_list(payload.get("rust_plugins"), "rust_plugins")
    python_plugins = _assert_slug_list(payload.get("python_plugins"), "python_plugins")
    cargo_packages = _assert_slug_list(payload.get("cargo_packages"), "cargo_packages")
    mutation_cargo_packages = _assert_slug_list(
        payload.get("mutation_cargo_packages"), "mutation_cargo_packages"
    )
    mutation_jobs = _assert_mutation_jobs(payload.get("mutation_jobs"))
    release_validation_tags = _assert_string_list(
        payload.get("release_validation_tags"), "release_validation_tags"
    )
    rust_release_validation_tags = _assert_string_list(
        payload.get("rust_release_validation_tags"), "rust_release_validation_tags"
    )
    python_release_validation_tags = _assert_string_list(
        payload.get("python_release_validation_tags"), "python_release_validation_tags"
    )
    has_plugins = _assert_bool(payload.get("has_plugins"), "has_plugins", bool(plugins))
    has_rust_plugins = _assert_bool(
        payload.get("has_rust_plugins"), "has_rust_plugins", bool(rust_plugins)
    )
    has_python_plugins = _assert_bool(
        payload.get("has_python_plugins"), "has_python_plugins", bool(python_plugins)
    )
    plugin_count = _assert_count(payload.get("plugin_count"), "plugin_count", plugins)
    rust_plugin_count = _assert_count(
        payload.get("rust_plugin_count"), "rust_plugin_count", rust_plugins
    )
    python_plugin_count = _assert_count(
        payload.get("python_plugin_count"), "python_plugin_count", python_plugins
    )
    has_mutation_cargo_packages = _assert_bool(
        payload.get("has_mutation_cargo_packages"),
        "has_mutation_cargo_packages",
        bool(mutation_cargo_packages),
    )
    has_release_validation_tags = _assert_bool(
        payload.get("has_release_validation_tags"),
        "has_release_validation_tags",
        bool(release_validation_tags),
    )
    has_rust_release_validation_tags = _assert_bool(
        payload.get("has_rust_release_validation_tags"),
        "has_rust_release_validation_tags",
        bool(rust_release_validation_tags),
    )
    has_python_release_validation_tags = _assert_bool(
        payload.get("has_python_release_validation_tags"),
        "has_python_release_validation_tags",
        bool(python_release_validation_tags),
    )
    if plugins != sorted(rust_plugins + python_plugins):
        raise AssertionError("plugins must equal the combined language plugin lists")
    if release_validation_tags != sorted(
        rust_release_validation_tags + python_release_validation_tags
    ):
        raise AssertionError(
            "release_validation_tags must equal the combined language tag lists"
        )

    print(
        json.dumps(
            {
                "plugins": plugins,
                "rust_plugins": rust_plugins,
                "python_plugins": python_plugins,
                "has_plugins": has_plugins,
                "has_rust_plugins": has_rust_plugins,
                "has_python_plugins": has_python_plugins,
                "plugin_count": plugin_count,
                "rust_plugin_count": rust_plugin_count,
                "python_plugin_count": python_plugin_count,
                "cargo_packages": cargo_packages,
                "mutation_cargo_packages": mutation_cargo_packages,
                "mutation_jobs": mutation_jobs,
                "has_mutation_cargo_packages": has_mutation_cargo_packages,
                "release_validation_tags": release_validation_tags,
                "rust_release_validation_tags": rust_release_validation_tags,
                "python_release_validation_tags": python_release_validation_tags,
                "has_release_validation_tags": has_release_validation_tags,
                "has_rust_release_validation_tags": has_rust_release_validation_tags,
                "has_python_release_validation_tags": has_python_release_validation_tags,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
