# Copyright 2026
# SPDX-License-Identifier: Apache-2.0
"""Catalog behavior at discovery, CI selection, release, coverage, and CLI boundaries."""

import json
import subprocess
import sys
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

from tools import plugin_catalog as catalog

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "tools" / "plugin_catalog.py"
SELECTION_VALIDATOR = REPO_ROOT / "tools" / "validate_ci_selection.py"
RUST_PATH = "plugins/rust/python-package/rust_demo"
OTHER_PATH = "plugins/rust/python-package/other_demo"
PYTHON_PATH = "plugins/python/python_demo"
ALL_PLUGINS = ["other_demo", "python_demo", "rust_demo"]


class CatalogTestCase(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / "Cargo.toml").write_text(f'[workspace]\nmembers = ["{RUST_PATH}", "{OTHER_PATH}"]\n')
        (self.root / "pyproject.toml").write_text(f'[tool.uv.workspace]\nmembers = ["{PYTHON_PATH}"]\n')
        self.create_plugin("rust_demo", "rust")
        self.create_plugin("other_demo", "rust")
        self.create_plugin("python_demo", "python")

    def create_plugin(self, slug: str, language: str) -> Path:
        parent = "plugins/python" if language == "python" else "plugins/rust/python-package"
        plugin = self.root / parent / slug
        module = plugin / f"cpex_{slug}"
        module.mkdir(parents=True)
        version = 'version = "1.0.0"' if language == "python" else 'dynamic = ["version"]'
        pyproject = f'[project]\nname = "cpex-{slug.replace("_", "-")}"\n{version}\n[project.entry-points."cpex.plugins"]\n{slug} = "cpex_{slug}.plugin:DemoPlugin"\n'
        if language == "rust":
            pyproject += f'[tool.maturin]\nmodule-name = "cpex_{slug}.{slug}_rust"\npython-source = "."\n'
            (plugin / "Cargo.toml").write_text(f'[package]\nname = "{slug}"\nversion = "1.0.0"\nrepository = "https://github.com/IBM/cpex-plugins"\n')
        (plugin / "pyproject.toml").write_text(pyproject)
        (plugin / "Makefile").touch()
        (plugin / "README.md").touch()
        (module / "__init__.py").touch()
        (module / "plugin-manifest.yaml").write_text(f'version: "1.0.0"\nkind: "cpex_{slug}.plugin.DemoPlugin"\n')
        return plugin

    def run_catalog(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), args[0], str(self.root), *args[1:]],
            text=True,
            capture_output=True,
            check=False,
        )

    def selection(self, paths: list[str]) -> dict:
        # Control only the Git boundary; discovery and routing use real fixture files.
        with patch.object(catalog, "_git_changed_paths", return_value=paths):
            return catalog.ci_selection(self.root, "diff", "base", "head")

    def assert_invalid_edit(self, file: Path, content: str, error: str) -> None:
        original = file.read_text()
        file.write_text(content)
        try:
            with self.assertRaisesRegex(catalog.CatalogError, error):
                catalog.discover_plugins(self.root)
        finally:
            file.write_text(original)


class DiscoveryTests(CatalogTestCase):
    def test_discovers_typed_records_from_both_managed_roots(self) -> None:
        records = {record.slug: record for record in catalog.discover_plugins(self.root)}
        self.assertEqual(set(records), set(ALL_PLUGINS))
        for slug, language, path in (("rust_demo", "rust", RUST_PATH), ("python_demo", "python", PYTHON_PATH)):
            with self.subTest(language=language):
                record = records[slug]
                self.assertEqual(record.language, language)
                self.assertEqual(record.path, path)
                self.assertEqual(record.package_name, f"cpex-{slug.replace('_', '-')}")
                self.assertEqual(record.module_name, f"cpex_{slug}")
                self.assertEqual(record.cargo_package_name, slug if language == "rust" else None)
                self.assertEqual(record.kind, f"cpex_{slug}.plugin.DemoPlugin")
                self.assertEqual(record.version, "1.0.0")

    def test_requires_a_manifest(self) -> None:
        (self.root / RUST_PATH / "cpex_rust_demo/plugin-manifest.yaml").unlink()
        with self.assertRaisesRegex(catalog.CatalogError, "missing required path"):
            catalog.discover_plugins(self.root)

    def test_rejects_duplicate_slugs_across_languages(self) -> None:
        self.create_plugin("rust_demo", "python")
        with self.assertRaisesRegex(catalog.CatalogError, "Duplicate plugin slug"):
            catalog.discover_plugins(self.root)

    def test_ignores_manifests_outside_managed_roots(self) -> None:
        outside = self.root / "examples/plugin-manifest.yaml"
        outside.parent.mkdir()
        outside.write_text("invalid example manifest\n")
        self.assertEqual(len(catalog.discover_plugins(self.root)), 3)

    def test_rejects_invalid_plugin_slug(self) -> None:
        plugin = self.root / RUST_PATH
        plugin.rename(plugin.with_name("Invalid-Name"))
        with self.assertRaisesRegex(catalog.CatalogError, "plugin slug"):
            catalog.discover_plugins(self.root)

    def test_rejects_packaging_metadata_that_cannot_load_or_release(self) -> None:
        cases = [
            (RUST_PATH, "pyproject.toml", 'name = "cpex-rust-demo"', 'name = "wrong"', "package name"),
            (RUST_PATH, "Cargo.toml", 'name = "rust_demo"', 'name = "wrong"', r"\[package\].name"),
            (RUST_PATH, "pyproject.toml", 'dynamic = ["version"]', 'version = "1.0.0"', "dynamic version"),
            (RUST_PATH, "pyproject.toml", "rust_demo_rust", "wrong_rust", "module-name"),
            (RUST_PATH, "pyproject.toml", 'python-source = "."', 'python-source = "src"', "python-source"),
            (RUST_PATH, "Cargo.toml", "https://github.com/IBM/cpex-plugins", "https://example.test", "repository metadata"),
            (PYTHON_PATH, "pyproject.toml", 'version = "1.0.0"', 'dynamic = ["version"]', "must be static"),
        ]
        for path, filename, old, new, error in cases:
            with self.subTest(path=path, change=new):
                file = self.root / path / filename
                self.assert_invalid_edit(file, file.read_text().replace(old, new), error)

    def test_requires_matching_manifest_and_entry_point(self) -> None:
        manifest = self.root / RUST_PATH / "cpex_rust_demo/plugin-manifest.yaml"
        project = self.root / RUST_PATH / "pyproject.toml"
        cases = [
            (manifest, 'version: "1.0.0"\n', "Missing kind"),
            (manifest, 'version: "1.0.0"\nkind: "cpex_rust_demo.plugin.OtherPlugin"\n', "kind mismatch"),
            (manifest, 'version: "1.0.0"\nkind: "cpex_rust_demo.plugin:DemoPlugin"\n', "canonical module.object"),
            (project, project.read_text().replace('[project.entry-points."cpex.plugins"]', "[project.entry-points.other]"), "entry-points"),
            (project, project.read_text().replace("plugin:DemoPlugin", "plugin.DemoPlugin"), "module:object"),
        ]
        for file, content, error in cases:
            with self.subTest(error=error):
                self.assert_invalid_edit(file, content, error)

    def test_requires_manifest_version_to_match_language_version_source(self) -> None:
        for path, slug in ((RUST_PATH, "rust_demo"), (PYTHON_PATH, "python_demo")):
            with self.subTest(slug=slug):
                manifest = self.root / path / f"cpex_{slug}/plugin-manifest.yaml"
                self.assert_invalid_edit(manifest, manifest.read_text().replace('"1.0.0"', '"2.0.0"'), "version mismatch")

    def test_accepts_manifest_comments(self) -> None:
        manifest = self.root / RUST_PATH / "cpex_rust_demo/plugin-manifest.yaml"
        manifest.write_text('version: "1.0.0" # release\nkind: cpex_rust_demo.plugin.DemoPlugin # loader\n')
        catalog.discover_plugins(self.root)

    def test_enforces_language_appropriate_workspace_membership(self) -> None:
        cases = [
            ("Cargo.toml", "[workspace]\nmembers = []\n", "missing from the top-level Cargo workspace"),
            ("pyproject.toml", "[tool.uv.workspace]\nmembers = []\n", "missing from the root uv workspace"),
            ("Cargo.toml", f'[workspace]\nmembers = ["{RUST_PATH}", "{OTHER_PATH}", "{PYTHON_PATH}"]\n', "must not be Cargo workspace members"),
        ]
        for filename, content, error in cases:
            with self.subTest(filename=filename, error=error):
                self.assert_invalid_edit(self.root / filename, content, error)

    def test_malformed_metadata_reports_a_catalog_error(self) -> None:
        cases = [
            ("Cargo.toml", "[workspace", "Invalid TOML"),
            ("Cargo.toml", 'workspace = "invalid"\n', "must define"),
            (f"{RUST_PATH}/pyproject.toml", "[project", "Invalid TOML"),
            (f"{RUST_PATH}/pyproject.toml", 'project = "invalid"\n', "must be a table"),
            (f"{RUST_PATH}/Cargo.toml", 'package = "invalid"\n', "must be a table"),
        ]
        for filename, content, error in cases:
            with self.subTest(filename=filename, content=content):
                self.assert_invalid_edit(self.root / filename, content, error)


class SelectionTests(CatalogTestCase):
    def test_all_mode_reports_complete_language_and_job_contract(self) -> None:
        self.assertEqual(
            catalog.ci_selection(self.root, "all"),
            {
                "plugins": ALL_PLUGINS,
                "rust_plugins": ["other_demo", "rust_demo"],
                "python_plugins": ["python_demo"],
                "has_plugins": True,
                "has_rust_plugins": True,
                "has_python_plugins": True,
                "plugin_count": 3,
                "rust_plugin_count": 2,
                "python_plugin_count": 1,
                "cargo_packages": ["other_demo", "rust_demo"],
                "mutation_cargo_packages": ["other_demo", "rust_demo"],
                "has_mutation_cargo_packages": True,
                "mutation_jobs": [
                    {"cargo_package": "other_demo", "in_diff": False, "test_packages": []},
                    {"cargo_package": "rust_demo", "in_diff": False, "test_packages": []},
                ],
                "release_validation_tags": [],
                "rust_release_validation_tags": [],
                "python_release_validation_tags": [],
                "has_release_validation_tags": False,
                "has_rust_release_validation_tags": False,
                "has_python_release_validation_tags": False,
            },
        )

    def test_diff_selects_affected_plugins(self) -> None:
        cases = [
            ([f"{RUST_PATH}/src/lib.rs"], ["rust_demo"]),
            ([f"{PYTHON_PATH}/cpex_python_demo/plugin.py"], ["python_demo"]),
            ([f"{RUST_PATH}/README.md", f"{PYTHON_PATH}/README.md"], ["python_demo", "rust_demo"]),
            (["plugins/tests/rust_demo/test_plugin.py"], ["rust_demo"]),
            (["plugins/tests/python_demo/test_plugin.py"], ["python_demo"]),
            (["plugins/tests/conftest.py"], ALL_PLUGINS),
            (["plugins/tests/unknown/test_plugin.py"], ALL_PLUGINS),
            (["Cargo.lock"], ALL_PLUGINS),
            (["Cargo.lock", f"{RUST_PATH}/src/lib.rs"], ["rust_demo"]),
            (["Makefile"], ALL_PLUGINS),
            (["Cargo.toml"], ALL_PLUGINS),
            (["pyproject.toml"], ALL_PLUGINS),
            (["uv.lock"], ALL_PLUGINS),
            ([".github/workflows/ci-rust-python-package.yaml"], ALL_PLUGINS),
            ([".cargo/mutants.toml"], ALL_PLUGINS),
            ([".config/nextest.toml"], ALL_PLUGINS),
            (["deny.toml"], ALL_PLUGINS),
            (["tools/plugin_catalog.py"], ALL_PLUGINS),
            (["TESTING.md"], ALL_PLUGINS),
            (["tests/test_plugin_catalog.py"], []),
            (["CONTRIBUTING.md"], []),
            ([], []),
        ]
        for paths, expected in cases:
            with self.subTest(paths=paths):
                result = self.selection(paths)
                self.assertEqual(result["plugins"], expected)
                self.assertEqual(result["has_plugins"], bool(expected))
                self.assertEqual(result["plugin_count"], len(expected))

    def test_mutation_jobs_follow_rust_source_changes(self) -> None:
        for paths, expected in (
            ([f"{RUST_PATH}/src/lib.rs"], [{"cargo_package": "rust_demo", "in_diff": True, "test_packages": []}]),
            ([f"{PYTHON_PATH}/cpex_python_demo/plugin.py"], []),
            (["plugins/tests/rust_demo/test_plugin.py"], []),
            ([".config/nextest.toml"], []),
        ):
            with self.subTest(paths=paths):
                result = self.selection(paths)
                self.assertEqual(result["mutation_jobs"], expected)
                self.assertEqual(result["has_mutation_cargo_packages"], bool(expected))

    def test_shared_crate_mutation_runs_only_its_rust_dependents(self) -> None:
        manifest = self.root / RUST_PATH / "Cargo.toml"
        manifest.write_text(manifest.read_text() + "[dependencies]\ncpex_framework_bridge = { workspace = true }\n")
        result = self.selection(["crates/framework_bridge/src/lib.rs"])
        self.assertEqual(result["plugins"], ALL_PLUGINS)
        self.assertEqual(
            result["mutation_jobs"],
            [
                {"cargo_package": "cpex_framework_bridge", "in_diff": True, "test_packages": ["rust_demo"]},
            ],
        )


class ReleaseTests(CatalogTestCase):
    def test_resolves_canonical_tags_for_each_language(self) -> None:
        for tag, slug, language, path in (
            ("rust-demo-v1.0.0", "rust_demo", "rust", RUST_PATH),
            ("python-demo-v1.0.0", "python_demo", "python", PYTHON_PATH),
        ):
            with self.subTest(tag=tag):
                record = catalog.release_info(self.root, tag)
                self.assertEqual((record.slug, record.language, record.path, record.version), (slug, language, path, "1.0.0"))

    def test_rejects_unknown_noncanonical_and_wrong_version_tags(self) -> None:
        for tag in ("v1.0.0", "unknown-v1.0.0", "rust_demo-v1.0.0", "rust-demo-v2.0.0"):
            with self.subTest(tag=tag), self.assertRaises(catalog.CatalogError):
                catalog.release_info(self.root, tag)


class GitIntegrationTests(CatalogTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.git("init")
        self.git("config", "user.name", "Catalog Tests")
        self.git("config", "user.email", "catalog@example.test")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.hooksPath", str(self.root / "no-hooks"))
        self.commit()
        self.base = self.git("rev-parse", "HEAD")

    def git(self, *args: str) -> str:
        return subprocess.run(["git", *args], cwd=self.root, text=True, capture_output=True, check=True).stdout.strip()

    def commit(self) -> None:
        self.git("add", ".")
        self.git("commit", "-s", "-m", "Catalog fixture")

    def test_diff_cli_routes_changes_and_version_bumps_for_both_languages(self) -> None:
        for path, slug, filename in ((RUST_PATH, "rust_demo", "Cargo.toml"), (PYTHON_PATH, "python_demo", "pyproject.toml")):
            version_file = self.root / path / filename
            version_file.write_text(version_file.read_text().replace('"1.0.0"', '"1.1.0"'))
            manifest = self.root / path / f"cpex_{slug}/plugin-manifest.yaml"
            manifest.write_text(manifest.read_text().replace('"1.0.0"', '"1.1.0"'))
        source = self.root / RUST_PATH / "src/lib.rs"
        source.parent.mkdir()
        source.write_text("// changed Rust source\n")
        self.commit()

        changed = self.run_catalog("changed", self.base, "HEAD")
        self.assertEqual(changed.returncode, 0, changed.stderr)
        self.assertEqual(json.loads(changed.stdout), {"plugins": ["python_demo", "rust_demo"]})
        selection = self.run_catalog("ci-selection", "diff", self.base, "HEAD")
        self.assertEqual(selection.returncode, 0, selection.stderr)
        payload = json.loads(selection.stdout)
        self.assertEqual(payload["cargo_packages"], ["rust_demo"])
        self.assertEqual(payload["rust_release_validation_tags"], ["rust-demo-v1.1.0"])
        self.assertEqual(payload["python_release_validation_tags"], ["python-demo-v1.1.0"])
        self.assertEqual(payload["release_validation_tags"], ["python-demo-v1.1.0", "rust-demo-v1.1.0"])
        self.assertEqual(payload["mutation_cargo_packages"], ["rust_demo"])

    def test_new_plugin_is_validated_for_initial_release(self) -> None:
        self.create_plugin("new_demo", "python")
        workspace = self.root / "pyproject.toml"
        workspace.write_text(f'[tool.uv.workspace]\nmembers = ["{PYTHON_PATH}", "plugins/python/new_demo"]\n')
        self.commit()
        result = catalog.ci_selection(self.root, "diff", self.base, "HEAD")
        self.assertEqual(result["python_release_validation_tags"], ["new-demo-v1.0.0"])

    def test_unchanged_version_does_not_trigger_release(self) -> None:
        manifest = self.root / RUST_PATH / "Cargo.toml"
        manifest.write_text(manifest.read_text() + "# metadata edit\n")
        self.commit()
        result = catalog.ci_selection(self.root, "diff", self.base, "HEAD")
        self.assertEqual(result["plugins"], ["rust_demo"])
        self.assertEqual(result["release_validation_tags"], [])


class CoverageTests(CatalogTestCase):
    def report(self, entries: dict[str, list[str]]) -> Path:
        classes = []
        for filename, hits in entries.items():
            lines = "".join(f'<line number="{number}" hits="{hit}"/>' for number, hit in enumerate(hits, 1))
            classes.append(f'<class filename="{filename}"><lines>{lines}</lines></class>')
        report = self.root / "coverage.xml"
        report.write_text("<coverage><packages><package><classes>" + "".join(classes) + "</classes></package></packages></coverage>")
        return report

    def test_counts_each_rust_plugin_and_ignores_non_plugin_code(self) -> None:
        report = self.report(
            {
                f"{RUST_PATH}/src/lib.rs": ["1", "0"],
                r"C:\repo\plugins\rust\python-package\other_demo\src\lib.rs": ["1", "1", "1", "0"],
                "crates/framework_bridge/src/lib.rs": ["0"],
                f"{PYTHON_PATH}/cpex_python_demo/plugin.py": ["0"],
            }
        )
        payload = catalog.coverage_check(self.root, report, 50)
        self.assertEqual(
            payload["plugins"],
            {
                "rust_demo": {"covered_lines": 1, "valid_lines": 2, "line_rate": 50.0},
                "other_demo": {"covered_lines": 3, "valid_lines": 4, "line_rate": 75.0},
            },
        )
        self.assertEqual(payload["minimum_plugin"], "rust_demo")
        self.assertEqual(payload["minimum_line_rate"], 50.0)
        with self.assertRaisesRegex(catalog.CatalogError, "below 50.10%"):
            catalog.coverage_check(self.root, report, 50.1)

    def test_rejects_incomplete_or_invalid_coverage(self) -> None:
        cases = [
            ({f"{RUST_PATH}/src/lib.rs": ["1"]}, None, "missing plugin coverage"),
            ({f"{RUST_PATH}/src/lib.rs": ["1"]}, ["unknown"], "Unknown expected"),
            ({"plugins/rust/python-package/unknown/src/lib.rs": ["1"]}, None, "unknown plugin coverage"),
            ({f"{RUST_PATH}/src/lib.rs": ["1"], f"{OTHER_PATH}/src/lib.rs": ["1"]}, ["rust_demo"], "unexpected plugin coverage"),
            ({f"{RUST_PATH}/src/lib.rs": []}, ["rust_demo"], "no counted coverage lines"),
            ({f"{RUST_PATH}/src/lib.rs": ["NaN"]}, ["rust_demo"], "Invalid coverage hit count"),
        ]
        for entries, expected, error in cases:
            with self.subTest(error=error):
                report = self.report(entries)
                with self.assertRaisesRegex(catalog.CatalogError, error):
                    catalog.coverage_check(self.root, report, 50, expected)


class CliTests(CatalogTestCase):
    def test_json_commands_and_scalar_fields(self) -> None:
        records = catalog.discover_plugins(self.root)
        cases = [
            (("validate",), {"status": "ok"}),
            (("list",), {"plugins": [asdict(record) for record in records]}),
            (("ci-selection", "all"), catalog.ci_selection(self.root, "all")),
            (("ci-selection-field", "all", "", "", "plugins"), ALL_PLUGINS),
            (("ci-selection-field", "all", "", "", "has_plugins"), True),
            (("ci-selection-field", "all", "", "", "plugin_count"), 3),
        ]
        for args, expected in cases:
            with self.subTest(args=args):
                result = self.run_catalog(*args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), expected)
        result = self.run_catalog("release-info-field", "python-demo-v1.0.0", "kind")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "cpex_python_demo.plugin.DemoPlugin")

    def test_errors_exit_cleanly_without_tracebacks(self) -> None:
        (self.root / RUST_PATH / "pyproject.toml").write_text("[project")
        result = self.run_catalog("validate")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Invalid TOML", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.stdout, "")


class SelectionValidatorTests(CatalogTestCase):
    def validate(self, payload: dict) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SELECTION_VALIDATOR)],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            check=False,
        )

    def test_reemits_complete_catalog_selection(self) -> None:
        payload = catalog.ci_selection(self.root, "all")
        result = self.validate(payload)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), payload)

    def test_rejects_malformed_and_inconsistent_job_inputs(self) -> None:
        cases = [
            ("python_plugins", None),
            ("plugins", ["../invalid"]),
            ("has_plugins", "true"),
            ("has_plugins", False),
            ("plugin_count", 99),
            ("plugin_count", True),
            ("python_plugins", ["other_plugin"]),
            ("release_validation_tags", ["python-demo-v1.0.0"]),
            ("mutation_jobs", [{"cargo_package": "rust_demo", "in_diff": "true", "test_packages": []}]),
        ]
        for field, value in cases:
            with self.subTest(field=field, value=value):
                payload = catalog.ci_selection(self.root, "all")
                if value is None:
                    del payload[field]
                else:
                    payload[field] = value
                result = self.validate(payload)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
