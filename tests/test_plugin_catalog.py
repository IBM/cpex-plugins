import json
import os
import ast
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path
import re


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "tools" / "plugin_catalog.py"


def run_catalog(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["python3", str(SCRIPT), *args],
        cwd=cwd or REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


class PluginCatalogTests(unittest.TestCase):
    def _extract_workflow_job_section(self, workflow: str, job_name: str) -> str:
        lines = workflow.splitlines()
        in_jobs = False
        job_header = f"  {job_name}:"
        section_lines: list[str] = []

        for line in lines:
            if line == "jobs:":
                in_jobs = True
                continue
            if not in_jobs:
                continue
            if line.startswith("  ") and not line.startswith("    "):
                if section_lines:
                    break
                if line == job_header:
                    section_lines.append(line)
                continue
            if section_lines:
                section_lines.append(line)

        self.assertTrue(section_lines, f"expected to find workflow job {job_name!r}")
        return "\n".join(section_lines) + "\n"

    def _source_tree_has_extension(self, package_dir: Path, module_name: str) -> bool:
        return any(package_dir.glob(f"{module_name}*.so")) or any(
            package_dir.glob(f"{module_name}*.pyd")
        )

    def _create_plugin(self, root: Path, slug: str) -> Path:
        plugin_dir = root / "plugins" / "rust" / "python-package" / slug
        package_dir = plugin_dir / f"cpex_{slug}"
        class_name = f"{slug.title().replace('_', '')}Plugin"
        manifest_kind = f"cpex_{slug}.{slug}.{class_name}"
        entry_point_kind = f"cpex_{slug}.{slug}:{class_name}"
        package_dir.mkdir(parents=True)
        (plugin_dir / "pyproject.toml").write_text(
            (
                f"[project]\nname = \"cpex-{slug.replace('_', '-')}\"\ndynamic = [\"version\"]\n\n"
                "[project.entry-points.\"cpex.plugins\"]\n"
                f"{slug} = \"{entry_point_kind}\"\n\n"
                "[tool.maturin]\n"
                f"module-name = \"cpex_{slug}.{slug}_rust\"\n"
                "python-source = \".\"\n"
            )
        )
        (plugin_dir / "Cargo.toml").write_text(
            f"[package]\nname = \"{slug}\"\nversion = \"0.0.1\"\nrepository = \"https://github.com/IBM/cpex-plugins\"\n"
        )
        (plugin_dir / "Makefile").write_text("all:\n\t@true\n")
        (plugin_dir / "README.md").write_text(f"# {slug}\n")
        (package_dir / "__init__.py").write_text("")
        (package_dir / "plugin-manifest.yaml").write_text(
            f'description: "{slug}"\nauthor: "ContextForge Team"\nversion: "0.0.1"\nkind: "{manifest_kind}"\navailable_hooks:\n  - "tool_pre_invoke"\n'
        )
        return plugin_dir

    def _parse_manifest_defaults(self, manifest_path: Path) -> dict[str, object]:
        defaults: dict[str, object] = {}
        in_defaults = False
        for line in manifest_path.read_text().splitlines():
            if line == "default_configs:":
                in_defaults = True
                continue
            if in_defaults and not line.startswith("  "):
                break
            if not in_defaults:
                continue
            key, _, raw_value = line.strip().partition(":")
            value = raw_value.strip()
            if value in {"true", "false"}:
                defaults[key] = value == "true"
            elif value == "[]":
                defaults[key] = []
            elif value.startswith('"') or value.startswith("'"):
                defaults[key] = ast.literal_eval(value)
            else:
                defaults[key] = int(value)
        return defaults

    def _extract_pii_runtime_defaults(self) -> dict[str, object]:
        config_text = (
            REPO_ROOT
            / "plugins"
            / "rust"
            / "python-package"
            / "pii_filter"
            / "src"
            / "config.rs"
        ).read_text()
        default_impl = config_text.split("impl Default for PIIConfig {", maxsplit=1)[1]
        constants: dict[str, int] = {}
        for name in (
            "DEFAULT_MAX_TEXT_BYTES",
            "DEFAULT_MAX_NESTED_DEPTH",
            "DEFAULT_MAX_COLLECTION_ITEMS",
        ):
            match = re.search(rf"{name}: usize = ([^;]+);", config_text)
            assert match is not None
            expr = match.group(1).replace("_", "")
            constants[name] = eval(expr, {"__builtins__": {}}, {})

        defaults: dict[str, object] = {}
        keys = (
            "detect_ssn",
            "detect_bsn",
            "detect_credit_card",
            "detect_email",
            "detect_phone",
            "detect_ip_address",
            "detect_date_of_birth",
            "detect_passport",
            "detect_driver_license",
            "detect_bank_account",
            "detect_medical_record",
            "default_mask_strategy",
            "redaction_text",
            "block_on_detection",
            "log_detections",
            "include_detection_details",
            "max_text_bytes",
            "max_nested_depth",
            "max_collection_items",
            "custom_patterns",
            "whitelist_patterns",
        )
        for key in keys:
            match = re.search(rf"{key}: ([^,]+),", default_impl)
            assert match is not None
            raw = match.group(1).strip()
            if raw in {"true", "false"}:
                defaults[key] = raw == "true"
            elif raw == "MaskingStrategy::Redact":
                defaults[key] = "redact"
            elif raw == '\"[REDACTED]\".to_string()':
                defaults[key] = "[REDACTED]"
            elif raw in constants:
                defaults[key] = constants[raw]
            elif raw == "Vec::new()":
                defaults[key] = []
            else:
                raise AssertionError(f"Unhandled default expression for {key}: {raw}")
        return defaults

    def test_repo_validates_managed_plugins_layout(self) -> None:
        result = run_catalog("validate", str(REPO_ROOT))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_repo_lists_all_managed_plugins(self) -> None:
        result = run_catalog("list", str(REPO_ROOT))
        self.assertEqual(result.returncode, 0, result.stderr)

        payload = json.loads(result.stdout)
        self.assertEqual(
            {entry["slug"] for entry in payload["plugins"]},
            {
                "encoded_exfil_detection",
                "pii_filter",
                "rate_limiter",
                "retry_with_backoff",
                "secrets_detection",
                "url_reputation",
            },
        )
        by_slug = {entry["slug"]: entry for entry in payload["plugins"]}
        self.assertEqual(
            {slug: entry["module_name"] for slug, entry in by_slug.items()},
            {
                "encoded_exfil_detection": "cpex_encoded_exfil_detection",
                "pii_filter": "cpex_pii_filter",
                "rate_limiter": "cpex_rate_limiter",
                "retry_with_backoff": "cpex_retry_with_backoff",
                "secrets_detection": "cpex_secrets_detection",
                "url_reputation": "cpex_url_reputation",
            },
        )
        self.assertEqual(
            {slug: entry["kind"] for slug, entry in by_slug.items()},
            {
                "encoded_exfil_detection": "cpex_encoded_exfil_detection.encoded_exfil_detection.EncodedExfilDetectorPlugin",
                "pii_filter": "cpex_pii_filter.pii_filter.PIIFilterPlugin",
                "rate_limiter": "cpex_rate_limiter.rate_limiter.RateLimiterPlugin",
                "retry_with_backoff": "cpex_retry_with_backoff.retry_with_backoff.RetryWithBackoffPlugin",
                "secrets_detection": "cpex_secrets_detection.secrets_detection.SecretsDetectionPlugin",
                "url_reputation": "cpex_url_reputation.url_reputation.URLReputationPlugin",
            },
        )

    def test_validator_rejects_manifest_missing_kind(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/demo_plugin"]\n'
                '[workspace.package]\nrepository = "https://github.com/IBM/cpex-plugins"\n',
            )
            plugin_dir = self._create_plugin(root, "demo_plugin")
            package_dir = plugin_dir / "cpex_demo_plugin"
            (package_dir / "plugin-manifest.yaml").write_text(
                textwrap.dedent(
                    """
                    description: "Demo plugin"
                    author: "ContextForge Team"
                    version: "0.0.1"
                    available_hooks:
                      - "tool_pre_invoke"
                    """
                ).strip()
                + "\n"
            )

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing kind", result.stderr.lower())

    def test_validator_rejects_manifest_kind_with_trailing_junk(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/demo_plugin"]\n'
                '[workspace.package]\nrepository = "https://github.com/IBM/cpex-plugins"\n',
            )
            plugin_dir = self._create_plugin(root, "demo_plugin")
            package_dir = plugin_dir / "cpex_demo_plugin"
            (package_dir / "plugin-manifest.yaml").write_text(
                textwrap.dedent(
                    """
                    description: "Demo plugin"
                    author: "ContextForge Team"
                    version: "0.0.1"
                    kind: "cpex_demo_plugin.demo_plugin.DemoPluginPlugin" garbage
                    available_hooks:
                      - "tool_pre_invoke"
                    """
                ).strip()
                + "\n"
            )

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("trailing content", result.stderr.lower())

    def test_validator_rejects_missing_plugin_entry_point(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/demo_plugin"]\n'
                '[workspace.package]\nrepository = "https://github.com/IBM/cpex-plugins"\n',
            )
            plugin_dir = self._create_plugin(root, "demo_plugin")
            (plugin_dir / "pyproject.toml").write_text(
                textwrap.dedent(
                    """
                    [project]
                    name = "cpex-demo-plugin"
                    dynamic = ["version"]

                    [tool.maturin]
                    module-name = "cpex_demo_plugin.demo_plugin_rust"
                    python-source = "."
                    """
                ).strip()
                + "\n"
            )

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("project.entry-points", result.stderr.lower())

    def test_validator_rejects_nondict_project_entry_points_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/demo_plugin"]\n'
                '[workspace.package]\nrepository = "https://github.com/IBM/cpex-plugins"\n',
            )
            plugin_dir = self._create_plugin(root, "demo_plugin")
            (plugin_dir / "pyproject.toml").write_text(
                textwrap.dedent(
                    """
                    [project]
                    name = "cpex-demo-plugin"
                    dynamic = ["version"]
                    entry-points = []

                    [tool.maturin]
                    module-name = "cpex_demo_plugin.demo_plugin_rust"
                    python-source = "."
                    """
                ).strip()
                + "\n"
            )

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("entry-points", result.stderr.lower())
            self.assertNotIn("traceback", result.stderr.lower())

    def test_validator_rejects_nondict_cpex_plugins_entry_points_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/demo_plugin"]\n'
                '[workspace.package]\nrepository = "https://github.com/IBM/cpex-plugins"\n',
            )
            plugin_dir = self._create_plugin(root, "demo_plugin")
            (plugin_dir / "pyproject.toml").write_text(
                textwrap.dedent(
                    """
                    [project]
                    name = "cpex-demo-plugin"
                    dynamic = ["version"]

                    [project.entry-points]
                    cpex.plugins = []

                    [tool.maturin]
                    module-name = "cpex_demo_plugin.demo_plugin_rust"
                    python-source = "."
                    """
                ).strip()
                + "\n"
            )

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cpex.plugins", result.stderr.lower())
            self.assertNotIn("traceback", result.stderr.lower())

    def test_validator_rejects_nonstring_sibling_cpex_plugins_entry_point_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/demo_plugin"]\n'
                '[workspace.package]\nrepository = "https://github.com/IBM/cpex-plugins"\n',
            )
            plugin_dir = self._create_plugin(root, "demo_plugin")
            (plugin_dir / "pyproject.toml").write_text(
                textwrap.dedent(
                    """
                    [project]
                    name = "cpex-demo-plugin"
                    dynamic = ["version"]

                    [project.entry-points."cpex.plugins"]
                    demo_plugin = "cpex_demo_plugin.demo_plugin:DemoPluginPlugin"
                    other = 123

                    [tool.maturin]
                    module-name = "cpex_demo_plugin.demo_plugin_rust"
                    python-source = "."
                    """
                ).strip()
                + "\n"
            )

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cpex.plugins", result.stderr.lower())
            self.assertNotIn("traceback", result.stderr.lower())

    def test_validator_rejects_missing_slug_specific_plugin_entry_point(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/demo_plugin"]\n'
                '[workspace.package]\nrepository = "https://github.com/IBM/cpex-plugins"\n',
            )
            plugin_dir = self._create_plugin(root, "demo_plugin")
            (plugin_dir / "pyproject.toml").write_text(
                textwrap.dedent(
                    """
                    [project]
                    name = "cpex-demo-plugin"
                    dynamic = ["version"]

                    [project.entry-points."cpex.plugins"]
                    other_plugin = "cpex_demo_plugin.demo_plugin:DemoPluginPlugin"

                    [tool.maturin]
                    module-name = "cpex_demo_plugin.demo_plugin_rust"
                    python-source = "."
                    """
                ).strip()
                + "\n"
            )

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("entry point", result.stderr.lower())

    def test_validator_rejects_mismatched_manifest_kind_and_entry_point(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/demo_plugin"]\n'
                '[workspace.package]\nrepository = "https://github.com/IBM/cpex-plugins"\n',
            )
            plugin_dir = self._create_plugin(root, "demo_plugin")
            package_dir = plugin_dir / "cpex_demo_plugin"
            (package_dir / "plugin-manifest.yaml").write_text(
                textwrap.dedent(
                    """
                    description: "Demo plugin"
                    author: "ContextForge Team"
                    version: "0.0.1"
                    kind: "cpex_demo_plugin.other.OtherPlugin"
                    available_hooks:
                      - "tool_pre_invoke"
                    """
                ).strip()
                + "\n"
            )

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("kind mismatch", result.stderr.lower())

    def test_validator_rejects_noncanonical_manifest_kind_separator(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/demo_plugin"]\n'
                '[workspace.package]\nrepository = "https://github.com/IBM/cpex-plugins"\n',
            )
            plugin_dir = self._create_plugin(root, "demo_plugin")
            package_dir = plugin_dir / "cpex_demo_plugin"
            (package_dir / "plugin-manifest.yaml").write_text(
                textwrap.dedent(
                    """
                    description: "Demo plugin"
                    author: "ContextForge Team"
                    version: "0.0.1"
                    kind: "cpex_demo_plugin.demo_plugin:DemoPluginPlugin"
                    available_hooks:
                      - "tool_pre_invoke"
                    """
                ).strip()
                + "\n"
            )

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("module.object", result.stderr.lower())

    def test_validator_rejects_equal_noncanonical_kind_strings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/demo_plugin"]\n'
                '[workspace.package]\nrepository = "https://github.com/IBM/cpex-plugins"\n',
            )
            plugin_dir = self._create_plugin(root, "demo_plugin")
            package_dir = plugin_dir / "cpex_demo_plugin"
            (plugin_dir / "pyproject.toml").write_text(
                textwrap.dedent(
                    """
                    [project]
                    name = "cpex-demo-plugin"
                    dynamic = ["version"]

                    [project.entry-points."cpex.plugins"]
                    demo_plugin = "cpex_demo_plugin.demo_plugin:DemoPluginPlugin"

                    [tool.maturin]
                    module-name = "cpex_demo_plugin.demo_plugin_rust"
                    python-source = "."
                    """
                ).strip()
                + "\n"
            )
            (package_dir / "plugin-manifest.yaml").write_text(
                textwrap.dedent(
                    """
                    description: "Demo plugin"
                    author: "ContextForge Team"
                    version: "0.0.1"
                    kind: "cpex_demo_plugin.demo_plugin:DemoPluginPlugin"
                    available_hooks:
                      - "tool_pre_invoke"
                    """
                ).strip()
                + "\n"
            )

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("module.object", result.stderr.lower())

    def test_validator_rejects_noncanonical_entry_point_with_canonical_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/demo_plugin"]\n'
                '[workspace.package]\nrepository = "https://github.com/IBM/cpex-plugins"\n',
            )
            plugin_dir = self._create_plugin(root, "demo_plugin")
            (plugin_dir / "pyproject.toml").write_text(
                textwrap.dedent(
                    """
                    [project]
                    name = "cpex-demo-plugin"
                    dynamic = ["version"]

                    [project.entry-points."cpex.plugins"]
                    demo_plugin = "cpex_demo_plugin.demo_plugin.DemoPluginPlugin"

                    [tool.maturin]
                    module-name = "cpex_demo_plugin.demo_plugin_rust"
                    python-source = "."
                    """
                ).strip()
                + "\n"
            )

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("module:object", result.stderr.lower())

    def test_validator_rejects_malformed_entry_point_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/demo_plugin"]\n'
                '[workspace.package]\nrepository = "https://github.com/IBM/cpex-plugins"\n',
            )
            plugin_dir = self._create_plugin(root, "demo_plugin")
            (plugin_dir / "pyproject.toml").write_text(
                textwrap.dedent(
                    """
                    [project]
                    name = "cpex-demo-plugin"
                    dynamic = ["version"]

                    [project.entry-points."cpex.plugins"]
                    demo_plugin = "cpex_demo_plugin.demo_plugin:"

                    [tool.maturin]
                    module-name = "cpex_demo_plugin.demo_plugin_rust"
                    python-source = "."
                    """
                ).strip()
                + "\n"
            )

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("module:object", result.stderr.lower())
            self.assertNotIn("traceback", result.stderr.lower())

    def test_validator_rejects_nested_object_kind_reference(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/demo_plugin"]\n'
                '[workspace.package]\nrepository = "https://github.com/IBM/cpex-plugins"\n',
            )
            plugin_dir = self._create_plugin(root, "demo_plugin")
            package_dir = plugin_dir / "cpex_demo_plugin"
            (plugin_dir / "pyproject.toml").write_text(
                textwrap.dedent(
                    """
                    [project]
                    name = "cpex-demo-plugin"
                    dynamic = ["version"]

                    [project.entry-points."cpex.plugins"]
                    demo_plugin = "cpex_demo_plugin.demo_plugin:DemoPluginPlugin"

                    [tool.maturin]
                    module-name = "cpex_demo_plugin.demo_plugin_rust"
                    python-source = "."
                    """
                ).strip()
                + "\n"
            )
            (package_dir / "plugin-manifest.yaml").write_text(
                textwrap.dedent(
                    """
                    description: "Demo plugin"
                    author: "ContextForge Team"
                    version: "0.0.1"
                    kind: "cpex_demo_plugin.demo_plugin.DemoPluginPlugin.nested"
                    available_hooks:
                      - "tool_pre_invoke"
                    """
                ).strip()
                + "\n"
            )

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("kind mismatch", result.stderr.lower())

    def test_validator_rejects_entry_point_with_extras(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/demo_plugin"]\n'
                '[workspace.package]\nrepository = "https://github.com/IBM/cpex-plugins"\n',
            )
            plugin_dir = self._create_plugin(root, "demo_plugin")
            package_dir = plugin_dir / "cpex_demo_plugin"
            (plugin_dir / "pyproject.toml").write_text(
                textwrap.dedent(
                    """
                    [project]
                    name = "cpex-demo-plugin"
                    dynamic = ["version"]

                    [project.entry-points."cpex.plugins"]
                    demo_plugin = "cpex_demo_plugin.demo_plugin:DemoPluginPlugin[extra]"

                    [tool.maturin]
                    module-name = "cpex_demo_plugin.demo_plugin_rust"
                    python-source = "."
                    """
                ).strip()
                + "\n"
            )
            (package_dir / "plugin-manifest.yaml").write_text(
                textwrap.dedent(
                    """
                    description: "Demo plugin"
                    author: "ContextForge Team"
                    version: "0.0.1"
                    kind: "cpex_demo_plugin.demo_plugin.DemoPluginPlugin[extra]"
                    available_hooks:
                      - "tool_pre_invoke"
                    """
                ).strip()
                + "\n"
            )

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("module.object", result.stderr.lower())

    def test_validator_rejects_whitespace_padded_kind_reference(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/demo_plugin"]\n'
                '[workspace.package]\nrepository = "https://github.com/IBM/cpex-plugins"\n',
            )
            plugin_dir = self._create_plugin(root, "demo_plugin")
            package_dir = plugin_dir / "cpex_demo_plugin"
            (plugin_dir / "pyproject.toml").write_text(
                textwrap.dedent(
                    """
                    [project]
                    name = "cpex-demo-plugin"
                    dynamic = ["version"]

                    [project.entry-points."cpex.plugins"]
                    demo_plugin = " cpex_demo_plugin.demo_plugin:DemoPluginPlugin "

                    [tool.maturin]
                    module-name = "cpex_demo_plugin.demo_plugin_rust"
                    python-source = "."
                    """
                ).strip()
                + "\n"
            )
            (package_dir / "plugin-manifest.yaml").write_text(
                textwrap.dedent(
                    """
                    description: "Demo plugin"
                    author: "ContextForge Team"
                    version: "0.0.1"
                    kind: " cpex_demo_plugin.demo_plugin.DemoPluginPlugin "
                    available_hooks:
                      - "tool_pre_invoke"
                    """
                ).strip()
                + "\n"
            )

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("module.object", result.stderr.lower())

    def test_validator_rejects_nondict_project_table_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/demo_plugin"]\n'
                '[workspace.package]\nrepository = "https://github.com/IBM/cpex-plugins"\n',
            )
            plugin_dir = self._create_plugin(root, "demo_plugin")
            (plugin_dir / "pyproject.toml").write_text(
                textwrap.dedent(
                    """
                    project = []

                    [tool.maturin]
                    module-name = "cpex_demo_plugin.demo_plugin_rust"
                    python-source = "."
                    """
                ).strip()
                + "\n"
            )

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("project", result.stderr.lower())
            self.assertNotIn("traceback", result.stderr.lower())

    def test_validator_rejects_nondict_cargo_package_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/demo_plugin"]\n'
                '[workspace.package]\nrepository = "https://github.com/IBM/cpex-plugins"\n',
            )
            plugin_dir = self._create_plugin(root, "demo_plugin")
            (plugin_dir / "Cargo.toml").write_text("package = []\n")

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cargo.toml", result.stderr.lower())
            self.assertNotIn("traceback", result.stderr.lower())

    def test_validator_rejects_malformed_workspace_cargo_toml_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "plugins" / "rust" / "python-package").mkdir(parents=True)
            (root / "Cargo.toml").write_text("[workspace\nmembers = []\n")

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid toml", result.stderr.lower())
            self.assertNotIn("traceback", result.stderr.lower())

    def test_validator_rejects_nondict_workspace_table_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "plugins" / "rust" / "python-package").mkdir(parents=True)
            (root / "Cargo.toml").write_text("workspace = []\n")

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("workspace", result.stderr.lower())
            self.assertNotIn("traceback", result.stderr.lower())

    def test_validator_rejects_nonlist_workspace_members_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "plugins" / "rust" / "python-package").mkdir(parents=True)
            (root / "Cargo.toml").write_text("[workspace]\nmembers = \"demo_plugin\"\n")

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("workspace", result.stderr.lower())
            self.assertNotIn("traceback", result.stderr.lower())

    def test_validator_rejects_nonstr_workspace_member_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "plugins" / "rust" / "python-package").mkdir(parents=True)
            (root / "Cargo.toml").write_text('[workspace]\nmembers = ["plugins/rust/python-package/demo_plugin", 123]\n')

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("workspace", result.stderr.lower())
            self.assertNotIn("traceback", result.stderr.lower())

    def test_validator_rejects_nondict_workspace_package_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "plugins" / "rust" / "python-package").mkdir(parents=True)
            (root / "Cargo.toml").write_text("[workspace]\nmembers = []\npackage = []\n")

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("workspace.package", result.stderr.lower())
            self.assertNotIn("traceback", result.stderr.lower())

    def test_validator_rejects_nondict_project_dynamic_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/demo_plugin"]\n'
                '[workspace.package]\nrepository = "https://github.com/IBM/cpex-plugins"\n',
            )
            plugin_dir = self._create_plugin(root, "demo_plugin")
            (plugin_dir / "pyproject.toml").write_text(
                textwrap.dedent(
                    """
                    [project]
                    name = "cpex-demo-plugin"
                    dynamic = "version"

                    [project.entry-points."cpex.plugins"]
                    demo_plugin = "cpex_demo_plugin.demo_plugin:DemoPluginPlugin"

                    [tool.maturin]
                    module-name = "cpex_demo_plugin.demo_plugin_rust"
                    python-source = "."
                    """
                ).strip()
                + "\n"
            )

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("dynamic version", result.stderr.lower())
            self.assertNotIn("traceback", result.stderr.lower())

    def test_validator_rejects_nondict_tool_maturin_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/demo_plugin"]\n'
                '[workspace.package]\nrepository = "https://github.com/IBM/cpex-plugins"\n',
            )
            plugin_dir = self._create_plugin(root, "demo_plugin")
            (plugin_dir / "pyproject.toml").write_text(
                textwrap.dedent(
                    """
                    [project]
                    name = "cpex-demo-plugin"
                    dynamic = ["version"]

                    [project.entry-points."cpex.plugins"]
                    demo_plugin = "cpex_demo_plugin.demo_plugin:DemoPluginPlugin"

                    [tool]
                    maturin = []
                    """
                ).strip()
                + "\n"
            )

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("tool.maturin", result.stderr.lower())
            self.assertNotIn("traceback", result.stderr.lower())

    def test_validator_rejects_malformed_pyproject_toml_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/demo_plugin"]\n'
                '[workspace.package]\nrepository = "https://github.com/IBM/cpex-plugins"\n',
            )
            plugin_dir = self._create_plugin(root, "demo_plugin")
            (plugin_dir / "pyproject.toml").write_text("[project\nname = 'broken'\n")

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid toml", result.stderr.lower())
            self.assertNotIn("traceback", result.stderr.lower())

    def test_validator_rejects_malformed_cargo_toml_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/demo_plugin"]\n'
                '[workspace.package]\nrepository = "https://github.com/IBM/cpex-plugins"\n',
            )
            plugin_dir = self._create_plugin(root, "demo_plugin")
            (plugin_dir / "Cargo.toml").write_text("[package\nname = 'broken'\n")

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid toml", result.stderr.lower())
            self.assertNotIn("traceback", result.stderr.lower())

    def test_pii_manifest_defaults_match_runtime_defaults(self) -> None:
        manifest_defaults = self._parse_manifest_defaults(
            REPO_ROOT
            / "plugins"
            / "rust"
            / "python-package"
            / "pii_filter"
            / "cpex_pii_filter"
            / "plugin-manifest.yaml"
        )
        runtime_defaults = self._extract_pii_runtime_defaults()
        self.assertEqual(manifest_defaults, runtime_defaults)

    def test_validator_rejects_manifest_version_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/demo_plugin"]\n',
            )
            plugin_dir = self._create_plugin(root, "demo_plugin")
            package_dir = plugin_dir / "cpex_demo_plugin"
            (plugin_dir / "Cargo.toml").write_text(
                textwrap.dedent(
                    """
                    [package]
                    name = "demo_plugin"
                    version = "1.2.3"
                    repository = "https://github.com/IBM/cpex-plugins"
                    """
                ).strip()
                + "\n"
            )
            (package_dir / "plugin-manifest.yaml").write_text(
                textwrap.dedent(
                    """
                    description: "Demo plugin"
                    author: "ContextForge Team"
                    version: "9.9.9"
                    available_hooks:
                      - "tool_pre_invoke"
                    """
                ).strip()
                + "\n"
            )

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("version mismatch", result.stderr.lower())

    def test_validator_accepts_manifest_version_with_yaml_comments(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/demo_plugin"]\n'
                '[workspace.package]\nrepository = "https://github.com/IBM/cpex-plugins"\n',
            )
            plugin_dir = self._create_plugin(root, "demo_plugin")
            package_dir = plugin_dir / "cpex_demo_plugin"
            (plugin_dir / "Cargo.toml").write_text(
                textwrap.dedent(
                    """
                    [package]
                    name = "demo_plugin"
                    version = "1.2.3"
                    repository.workspace = true
                    """
                ).strip()
                + "\n"
            )
            (package_dir / "plugin-manifest.yaml").write_text(
                textwrap.dedent(
                    """
                    description: "Demo plugin"
                    author: "ContextForge Team"
                    version: "1.2.3"  # inline comment
                    kind: "cpex_demo_plugin.demo_plugin.DemoPluginPlugin"
                    available_hooks:
                      - "tool_pre_invoke"
                    """
                ).strip()
                + "\n"
            )

            result = run_catalog("validate", str(root))
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_validator_rejects_plugin_missing_from_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text('[workspace]\nmembers = []\n')
            self._create_plugin(root, "demo_plugin")

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("workspace", result.stderr.lower())

    def test_validator_allows_extra_workspace_members(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/demo_plugin", "plugins/rust/python-package/stale_plugin"]\n'
                '[workspace.package]\nrepository = "https://github.com/IBM/cpex-plugins"\n',
            )
            self._create_plugin(root, "demo_plugin")

            result = run_catalog("validate", str(root))
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_validator_ignores_plugin_manifests_outside_managed_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/demo_plugin"]\n',
            )
            self._create_plugin(root, "demo_plugin")
            stray_dir = root / "legacy_plugin"
            stray_package = stray_dir / "cpex_legacy_plugin"
            stray_package.mkdir(parents=True)
            (stray_package / "__init__.py").write_text("")
            (stray_package / "plugin-manifest.yaml").write_text(
                'description: "Legacy plugin"\nauthor: "ContextForge Team"\nversion: "0.0.1"\navailable_hooks:\n  - "tool_pre_invoke"\n'
            )

            result = run_catalog("validate", str(root))
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_changed_returns_plugins_for_git_diff(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            git = lambda *args: subprocess.run(  # noqa: E731
                ["git", *args],
                cwd=root,
                text=True,
                capture_output=True,
                check=True,
            )
            git("init")
            git("config", "user.name", "Test User")
            git("config", "user.email", "test@example.com")
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/rate_limiter"]\n',
            )

            readme = root / "plugins" / "rust" / "python-package" / "rate_limiter" / "README.md"
            readme.parent.mkdir(parents=True, exist_ok=True)
            readme.write_text("# Rate limiter\n")
            cargo = readme.parent / "Cargo.toml"
            cargo.write_text(
                "[package]\nname = \"rate_limiter\"\nversion = \"0.0.1\"\nrepository = \"https://github.com/IBM/cpex-plugins\"\n"
            )
            pyproject = readme.parent / "pyproject.toml"
            pyproject.write_text(
                "[project]\nname = \"cpex-rate-limiter\"\ndynamic = [\"version\"]\n\n"
                "[project.entry-points.\"cpex.plugins\"]\n"
                "rate_limiter = \"cpex_rate_limiter.rate_limiter:RateLimiterPlugin\"\n\n"
                "[tool.maturin]\nmodule-name = \"cpex_rate_limiter.rate_limiter_rust\"\npython-source = \".\"\n"
            )
            package_dir = readme.parent / "cpex_rate_limiter"
            package_dir.mkdir()
            (package_dir / "__init__.py").write_text("")
            (package_dir / "plugin-manifest.yaml").write_text(
                'description: "Rate limiter"\nauthor: "ContextForge Team"\nversion: "0.0.1"\nkind: "cpex_rate_limiter.rate_limiter.RateLimiterPlugin"\navailable_hooks:\n  - "tool_pre_invoke"\n'
            )
            (readme.parent / "Makefile").write_text("all:\n\t@true\n")
            (readme.parent / "tests").mkdir()
            git("add", ".")
            git("commit", "--no-verify", "-m", "seed layout")
            base_sha = git("rev-parse", "HEAD").stdout.strip()

            readme.write_text("# Rate limiter\n\nUpdated.\n")
            git("add", ".")
            git("commit", "--no-verify", "-m", "update readme")

            result = run_catalog("changed", str(root), base_sha, "HEAD")
            self.assertEqual(result.returncode, 0, result.stderr)

            payload = json.loads(result.stdout)
            self.assertEqual(payload["plugins"], ["rate_limiter"])

    def test_changed_skips_plugin_ci_for_repo_docs_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            git = lambda *args: subprocess.run(  # noqa: E731
                ["git", *args],
                cwd=root,
                text=True,
                capture_output=True,
                check=True,
            )
            git("init")
            git("config", "user.name", "Test User")
            git("config", "user.email", "test@example.com")
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/rate_limiter", "plugins/rust/python-package/pii_filter"]\n'
            )
            self._create_plugin(root, "rate_limiter")
            self._create_plugin(root, "pii_filter")
            (root / "README.md").write_text("# Repo\n")
            git("add", ".")
            git("commit", "--no-verify", "-m", "seed layout")
            base_sha = git("rev-parse", "HEAD").stdout.strip()

            (root / "README.md").write_text("# Repo\n\nUpdated docs.\n")
            git("add", ".")
            git("commit", "--no-verify", "-m", "update docs")

            result = run_catalog("changed", str(root), base_sha, "HEAD")
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["plugins"], ["pii_filter", "rate_limiter"])

    def test_changed_returns_only_modified_plugin_in_multi_plugin_repo(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            git = lambda *args: subprocess.run(  # noqa: E731
                ["git", *args],
                cwd=root,
                text=True,
                capture_output=True,
                check=True,
            )
            git("init")
            git("config", "user.name", "Test User")
            git("config", "user.email", "test@example.com")
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/rate_limiter", "plugins/rust/python-package/pii_filter"]\n'
                '[workspace.package]\nrepository = "https://github.com/IBM/cpex-plugins"\n',
            )
            self._create_plugin(root, "rate_limiter")
            self._create_plugin(root, "pii_filter")
            git("add", ".")
            git("commit", "--no-verify", "-m", "seed layout")
            base_sha = git("rev-parse", "HEAD").stdout.strip()

            (
                root
                / "plugins"
                / "rust"
                / "python-package"
                / "pii_filter"
                / "README.md"
            ).write_text("# pii_filter\n\nUpdated.\n")
            git("add", ".")
            git("commit", "--no-verify", "-m", "update pii filter readme")

            result = run_catalog("changed", str(root), base_sha, "HEAD")
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["plugins"], ["pii_filter"])

    def test_changed_skips_plugin_ci_for_root_makefile_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            git = lambda *args: subprocess.run(  # noqa: E731
                ["git", *args],
                cwd=root,
                text=True,
                capture_output=True,
                check=True,
            )
            git("init")
            git("config", "user.name", "Test User")
            git("config", "user.email", "test@example.com")
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/rate_limiter", "plugins/rust/python-package/pii_filter"]\n'
            )
            (root / "Makefile").write_text("help:\n\t@true\n")
            self._create_plugin(root, "rate_limiter")
            self._create_plugin(root, "pii_filter")
            git("add", ".")
            git("commit", "--no-verify", "-m", "seed layout")
            base_sha = git("rev-parse", "HEAD").stdout.strip()

            (root / "Makefile").write_text("help:\n\t@echo plugins-list\n")
            git("add", ".")
            git("commit", "--no-verify", "-m", "update root makefile")

            result = run_catalog("changed", str(root), base_sha, "HEAD")
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["plugins"], ["pii_filter", "rate_limiter"])

    def test_changed_returns_all_plugins_for_workflow_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            git = lambda *args: subprocess.run(  # noqa: E731
                ["git", *args],
                cwd=root,
                text=True,
                capture_output=True,
                check=True,
            )
            git("init")
            git("config", "user.name", "Test User")
            git("config", "user.email", "test@example.com")
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/rate_limiter", "plugins/rust/python-package/pii_filter"]\n'
            )
            self._create_plugin(root, "rate_limiter")
            self._create_plugin(root, "pii_filter")
            workflow_dir = root / ".github" / "workflows"
            workflow_dir.mkdir(parents=True)
            workflow = workflow_dir / "ci-rust-python-package.yaml"
            workflow.write_text("name: ci\n")
            git("add", ".")
            git("commit", "--no-verify", "-m", "seed layout")
            base_sha = git("rev-parse", "HEAD").stdout.strip()

            workflow.write_text("name: ci\non: pull_request\n")
            git("add", ".")
            git("commit", "--no-verify", "-m", "update workflow")

            result = run_catalog("changed", str(root), base_sha, "HEAD")
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["plugins"], ["pii_filter", "rate_limiter"])

    def test_release_info_accepts_canonical_tag(self) -> None:
        result = run_catalog("release-info", str(REPO_ROOT), "rate-limiter-v0.0.4")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["slug"], "rate_limiter")
        self.assertEqual(
            payload["kind"],
            "cpex_rate_limiter.rate_limiter.RateLimiterPlugin",
        )
        self.assertEqual(
            payload["release_wheel_matrix"],
            [
                {"runner": "ubuntu-latest", "platform": "linux-x86_64"},
                {"runner": "ubuntu-24.04-arm", "platform": "linux-aarch64"},
                {"runner": "ubuntu-24.04-s390x", "platform": "linux-s390x"},
                {"runner": "ubuntu-24.04-ppc64le", "platform": "linux-ppc64le"},
                {"runner": "macos-latest", "platform": "macos-arm64"},
                {"runner": "windows-latest", "platform": "windows-x86_64"},
            ],
        )

    def test_release_info_gives_pii_filter_the_same_target_matrix(self) -> None:
        result = run_catalog("release-info", str(REPO_ROOT), "pii-filter-v0.2.1")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["slug"], "pii_filter")
        self.assertEqual(
            payload["release_wheel_matrix"],
            [
                {"runner": "ubuntu-latest", "platform": "linux-x86_64"},
                {"runner": "ubuntu-24.04-arm", "platform": "linux-aarch64"},
                {"runner": "ubuntu-24.04-s390x", "platform": "linux-s390x"},
                {"runner": "ubuntu-24.04-ppc64le", "platform": "linux-ppc64le"},
                {"runner": "macos-latest", "platform": "macos-arm64"},
                {"runner": "windows-latest", "platform": "windows-x86_64"},
            ],
        )

    def test_release_info_rejects_noncanonical_tag(self) -> None:
        result = run_catalog("release-info", str(REPO_ROOT), "rate_limiter-v0.0.4")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("canonical", result.stderr.lower())

    def test_release_info_field_supports_kind(self) -> None:
        result = run_catalog("release-info-field", str(REPO_ROOT), "pii-filter-v0.2.1", "kind")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "cpex_pii_filter.pii_filter.PIIFilterPlugin")

    def test_ci_selection_returns_has_plugins_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            git = lambda *args: subprocess.run(  # noqa: E731
                ["git", *args],
                cwd=root,
                text=True,
                capture_output=True,
                check=True,
            )
            git("init")
            git("config", "user.name", "Test User")
            git("config", "user.email", "test@example.com")
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/rate_limiter", "plugins/rust/python-package/pii_filter"]\n'
            )
            self._create_plugin(root, "rate_limiter")
            self._create_plugin(root, "pii_filter")
            git("add", ".")
            git("commit", "--no-verify", "-m", "seed layout")
            base_sha = git("rev-parse", "HEAD").stdout.strip()

            (root / "README.md").write_text("# Repo docs only\n")
            git("add", ".")
            git("commit", "--no-verify", "-m", "docs only")

            result = run_catalog("ci-selection", str(root), "diff", base_sha, "HEAD")
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload, {"plugins": ["pii_filter", "rate_limiter"], "has_plugins": True})

    def test_ci_selection_treats_catalog_test_change_as_not_shared(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            git = lambda *args: subprocess.run(  # noqa: E731
                ["git", *args],
                cwd=root,
                text=True,
                capture_output=True,
                check=True,
            )
            git("init")
            git("config", "user.name", "Test User")
            git("config", "user.email", "test@example.com")
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/rate_limiter", "plugins/rust/python-package/pii_filter"]\n'
            )
            self._create_plugin(root, "rate_limiter")
            self._create_plugin(root, "pii_filter")
            git("add", ".")
            git("commit", "--no-verify", "-m", "seed layout")
            base_sha = git("rev-parse", "HEAD").stdout.strip()

            tests_dir = root / "tests"
            tests_dir.mkdir()
            (tests_dir / "test_plugin_catalog.py").write_text("# shared test change\n")
            git("add", ".")
            git("commit", "--no-verify", "-m", "catalog test change")

            result = run_catalog("ci-selection", str(root), "diff", base_sha, "HEAD")
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload, {"plugins": [], "has_plugins": False})

    def test_ci_selection_treats_shared_tool_changes_as_all_plugins(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            git = lambda *args: subprocess.run(  # noqa: E731
                ["git", *args],
                cwd=root,
                text=True,
                capture_output=True,
                check=True,
            )
            git("init")
            git("config", "user.name", "Test User")
            git("config", "user.email", "test@example.com")
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/rate_limiter", "plugins/rust/python-package/pii_filter"]\n'
            )
            self._create_plugin(root, "rate_limiter")
            self._create_plugin(root, "pii_filter")
            git("add", ".")
            git("commit", "--no-verify", "-m", "seed layout")
            base_sha = git("rev-parse", "HEAD").stdout.strip()

            tools_dir = root / "tools"
            tools_dir.mkdir()
            (tools_dir / "plugin_catalog.py").write_text("# shared tool change\n")
            git("add", ".")
            git("commit", "--no-verify", "-m", "shared tool input")

            result = run_catalog("ci-selection", str(root), "diff", base_sha, "HEAD")
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload, {"plugins": ["pii_filter", "rate_limiter"], "has_plugins": True})

    def test_ci_selection_treats_cargo_lock_change_as_not_shared(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            git = lambda *args: subprocess.run(  # noqa: E731
                ["git", *args],
                cwd=root,
                text=True,
                capture_output=True,
                check=True,
            )
            git("init")
            git("config", "user.name", "Test User")
            git("config", "user.email", "test@example.com")
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/rate_limiter", "plugins/rust/python-package/pii_filter"]\n'
            )
            self._create_plugin(root, "rate_limiter")
            self._create_plugin(root, "pii_filter")
            (root / "Cargo.lock").write_text("# seed\n")
            git("add", ".")
            git("commit", "--no-verify", "-m", "seed layout")
            base_sha = git("rev-parse", "HEAD").stdout.strip()

            (root / "Cargo.lock").write_text("# updated\n")
            git("add", ".")
            git("commit", "--no-verify", "-m", "lockfile update")

            result = run_catalog("ci-selection", str(root), "diff", base_sha, "HEAD")
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload, {"plugins": [], "has_plugins": False})

    def test_changed_returns_plugin_for_plugin_integration_test_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            git = lambda *args: subprocess.run(  # noqa: E731
                ["git", *args],
                cwd=root,
                text=True,
                capture_output=True,
                check=True,
            )
            git("init")
            git("config", "user.name", "Test User")
            git("config", "user.email", "test@example.com")
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/rate_limiter", "plugins/rust/python-package/pii_filter"]\n'
            )
            self._create_plugin(root, "rate_limiter")
            self._create_plugin(root, "pii_filter")
            integration_dir = root / "plugins" / "tests" / "pii_filter"
            integration_dir.mkdir(parents=True)
            (integration_dir / "test_integration.py").write_text("# seed\n")
            git("add", ".")
            git("commit", "--no-verify", "-m", "seed layout")
            base_sha = git("rev-parse", "HEAD").stdout.strip()

            (integration_dir / "test_integration.py").write_text("# updated\n")
            git("add", ".")
            git("commit", "--no-verify", "-m", "plugin integration change")

            result = run_catalog("ci-selection", str(root), "diff", base_sha, "HEAD")
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload, {"plugins": ["pii_filter"], "has_plugins": True})

    def test_ci_selection_treats_shared_crate_changes_as_all_plugins(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            git = lambda *args: subprocess.run(  # noqa: E731
                ["git", *args],
                cwd=root,
                text=True,
                capture_output=True,
                check=True,
            )
            git("init")
            git("config", "user.name", "Test User")
            git("config", "user.email", "test@example.com")
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/rate_limiter", "plugins/rust/python-package/pii_filter"]\n'
            )
            self._create_plugin(root, "rate_limiter")
            self._create_plugin(root, "pii_filter")
            shared_crate = root / "crates" / "framework_bridge" / "src"
            shared_crate.mkdir(parents=True)
            (shared_crate / "lib.rs").write_text("// shared crate change\n")
            git("add", ".")
            git("commit", "--no-verify", "-m", "seed layout")
            base_sha = git("rev-parse", "HEAD").stdout.strip()

            (shared_crate / "lib.rs").write_text("// shared crate change\n// update\n")
            git("add", ".")
            git("commit", "--no-verify", "-m", "shared crate change")

            result = run_catalog("ci-selection", str(root), "diff", base_sha, "HEAD")
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload, {"plugins": ["pii_filter", "rate_limiter"], "has_plugins": True})

    def test_ci_selection_field_prints_json_and_bool_scalars(self) -> None:
        result = run_catalog("ci-selection-field", str(REPO_ROOT), "all", "", "", "plugins")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(result.stdout),
            [
                "encoded_exfil_detection",
                "pii_filter",
                "rate_limiter",
                "retry_with_backoff",
                "secrets_detection",
                "url_reputation",
            ],
        )

        result = run_catalog("ci-selection-field", str(REPO_ROOT), "all", "", "", "has_plugins")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "true")

    def test_ci_selection_field_supports_diff_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            git = lambda *args: subprocess.run(  # noqa: E731
                ["git", *args],
                cwd=root,
                text=True,
                capture_output=True,
                check=True,
            )
            git("init")
            git("config", "user.name", "Test User")
            git("config", "user.email", "test@example.com")
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/rate_limiter", "plugins/rust/python-package/pii_filter"]\n'
                '[workspace.package]\nrepository = "https://github.com/IBM/cpex-plugins"\n'
            )
            self._create_plugin(root, "rate_limiter")
            self._create_plugin(root, "pii_filter")
            git("add", ".")
            git("commit", "--no-verify", "-m", "seed layout")
            base_sha = git("rev-parse", "HEAD").stdout.strip()

            makefile = root / "Makefile"
            makefile.write_text("help:\n\t@echo plugins-list\n")
            git("add", ".")
            git("commit", "--no-verify", "-m", "root makefile change")

            result = run_catalog(
                "ci-selection-field",
                str(root),
                "diff",
                base_sha,
                "HEAD",
                "plugins",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), ["pii_filter", "rate_limiter"])

    def test_ci_workflow_shared_paths_match_catalog_contract(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "ci-rust-python-package.yaml"
        ).read_text()
        expected_paths = {
            "Makefile",
            "Cargo.toml",
            "crates/**",
            "README.md",
            "DEVELOPING.md",
            "TESTING.md",
            "plugins/tests/**",
            "tools/**",
            ".github/workflows/ci-rust-python-package.yaml",
            ".github/workflows/release-rust-python-package.yaml",
        }
        actual_paths = {
            match.group(1)
            for match in re.finditer(r'- "([^"]+)"', workflow)
        }
        self.assertTrue(expected_paths.issubset(actual_paths))

    def test_catalog_workflow_paths_match_contract(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "ci-plugin-catalog.yaml"
        ).read_text()
        expected_paths = {
            "tests/test_plugin_catalog.py",
            "tools/plugin_catalog.py",
            ".github/workflows/ci-plugin-catalog.yaml",
            ".github/workflows/ci-rust-python-package.yaml",
            ".github/workflows/release-rust-python-package.yaml",
        }
        actual_paths = {
            match.group(1)
            for match in re.finditer(r'- "([^"]+)"', workflow)
        }
        self.assertTrue(expected_paths.issubset(actual_paths))

    def test_install_wheel_workflow_paths_match_contract(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "ci-install-built-wheel.yaml"
        ).read_text()
        expected_paths = {
            "tests/test_install_built_wheel.py",
            "plugins/rust/python-package/**",
            ".github/workflows/ci-install-built-wheel.yaml",
            ".github/workflows/release-rust-python-package.yaml",
        }
        actual_paths = {
            match.group(1)
            for match in re.finditer(r'- "([^"]+)"', workflow)
        }
        self.assertTrue(expected_paths.issubset(actual_paths))

    def test_validator_rejects_maturin_module_name_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/demo_plugin"]\n'
                '[workspace.package]\nrepository = "https://github.com/IBM/cpex-plugins"\n',
            )
            plugin_dir = self._create_plugin(root, "demo_plugin")
            (plugin_dir / "pyproject.toml").write_text(
                textwrap.dedent(
                    """
                    [project]
                    name = "cpex-demo-plugin"
                    dynamic = ["version"]

                    [tool.maturin]
                    module-name = "wrong.module"
                    python-source = "."
                    """
                ).strip()
                + "\n"
            )

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("module-name", result.stderr)

    def test_validator_rejects_maturin_python_source_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["plugins/rust/python-package/demo_plugin"]\n'
                '[workspace.package]\nrepository = "https://github.com/IBM/cpex-plugins"\n',
            )
            plugin_dir = self._create_plugin(root, "demo_plugin")
            (plugin_dir / "pyproject.toml").write_text(
                textwrap.dedent(
                    """
                    [project]
                    name = "cpex-demo-plugin"
                    dynamic = ["version"]

                    [tool.maturin]
                    module-name = "cpex_demo_plugin.demo_plugin_rust"
                    python-source = "python"
                    """
                ).strip()
                + "\n"
            )

            result = run_catalog("validate", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("python-source", result.stderr)

    def test_plugin_makefiles_expose_ci_targets(self) -> None:
        for slug in (
            "encoded_exfil_detection",
            "pii_filter",
            "rate_limiter",
            "retry_with_backoff",
            "secrets_detection",
            "url_reputation",
        ):
            makefile = (
                REPO_ROOT
                / "plugins"
                / "rust"
                / "python-package"
                / slug
                / "Makefile"
            )
            text = makefile.read_text()
            self.assertRegex(text, r"(?m)^\.PHONY:.*\binstall-wheel\b")
            self.assertRegex(text, r"(?m)^install-wheel:")
            self.assertRegex(text, r"(?m)^\.PHONY:.*\bci\b")
            self.assertRegex(text, r"(?m)^ci:")
            self.assertNotRegex(text, r"(?m)^ci:.*(?:^|\s)install(?:\s|$)")
            self.assertRegex(text, r"(?m)^ci:.*\binstall-wheel\b")

    def test_existing_benchmark_plugins_keep_bench_targets(self) -> None:
        for slug in ("pii_filter", "rate_limiter"):
            makefile = (
                REPO_ROOT
                / "plugins"
                / "rust"
                / "python-package"
                / slug
                / "Makefile"
            )
            text = makefile.read_text()
            self.assertRegex(text, r"(?m)^\.PHONY:.*\bbench-no-run\b")
            self.assertRegex(text, r"(?m)^bench-no-run:")

    def test_ci_workflow_uses_make_targets_for_plugin_checks(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "ci-rust-python-package.yaml"
        ).read_text()
        self.assertIn("concurrency:", workflow)
        self.assertIn("cancel-in-progress: true", workflow)
        self.assertIn("github.head_ref || github.ref_name", workflow)
        self.assertIn("push:\n    branches: [main]", workflow)
        self.assertIn("pull_request:\n    branches: [main]", workflow)
        self.assertIn('- "Makefile"', workflow)
        self.assertNotIn("pulls?state=open&head=", workflow)
        self.assertNotIn("dedupe:", workflow)
        self.assertIn("if: needs.validate-and-detect.outputs.has_plugins == 'true'", workflow)
        self.assertNotIn("tests/test_plugin_catalog.py", workflow)
        self.assertNotIn("tests/test_install_built_wheel.py", workflow)
        self.assertIn("python3 tools/plugin_catalog.py ci-selection . diff", workflow)
        self.assertIn("run: make ci", workflow)
        self.assertIn("shell: bash", workflow)
        self.assertIn("rustc --version", workflow)
        self.assertIn("working-directory: plugins/rust/python-package/${{ matrix.plugin }}", workflow)
        self.assertIn("release-validation:", workflow)
        self.assertIn("uses: ./.github/workflows/release-rust-python-package.yaml", workflow)
        self.assertIn("tag: retry-with-backoff-v0.1.1", workflow)
        self.assertIn("repository: testpypi", workflow)
        self.assertIn("publish_enabled: false", workflow)
        self.assertNotIn("tools/plugin_catalog.py ci-selection-field", workflow)
        self.assertNotIn("tools/plugin_catalog.py changed", workflow)
        self.assertNotIn("tools/plugin_catalog.py list", workflow)
        self.assertNotIn("dtolnay/rust-toolchain", workflow)
        self.assertNotRegex(workflow, r"run:\s*uv run pytest")
        self.assertNotRegex(workflow, r"run:\s*uv run maturin develop")
        self.assertNotIn("python3 - <<'PY'", workflow)
        self.assertIn("uv==0.9.30", workflow)
        self.assertIn("maturin==1.12.6", workflow)
        self.assertIn(
            "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
            workflow,
        )
        self.assertIn(
            "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
            workflow,
        )
        self.assertNotIn("actions/checkout@v4", workflow)
        self.assertNotIn("actions/setup-python@v5", workflow)
        self.assertNotRegex(
            workflow,
            r"defaults:\n\s+run:\n\s+shell: bash\n\s+working-directory: .*\$\{\{",
        )

    def test_catalog_workflow_runs_catalog_suite(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "ci-plugin-catalog.yaml"
        ).read_text()
        self.assertIn("name: CI Plugin Catalog", workflow)
        self.assertIn("concurrency:", workflow)
        self.assertIn("cancel-in-progress: true", workflow)
        self.assertIn("python3 -m unittest tests/test_plugin_catalog.py", workflow)
        self.assertNotIn("tests/test_install_built_wheel.py", workflow)
        self.assertNotIn("python3 tools/plugin_catalog.py ci-selection", workflow)
        self.assertIn(
            "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
            workflow,
        )
        self.assertIn(
            "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
            workflow,
        )

    def test_install_wheel_workflow_runs_install_suite(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "ci-install-built-wheel.yaml"
        ).read_text()
        self.assertIn("name: CI Install Built Wheel", workflow)
        self.assertIn("concurrency:", workflow)
        self.assertIn("cancel-in-progress: true", workflow)
        self.assertIn("python3 -m unittest tests/test_install_built_wheel.py", workflow)
        self.assertNotIn("tests/test_plugin_catalog.py", workflow)
        self.assertIn("uses: ./.github/workflows/release-rust-python-package.yaml", workflow)
        self.assertIn("publish_enabled: false", workflow)
        self.assertIn(
            "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
            workflow,
        )
        self.assertIn(
            "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
            workflow,
        )

    def test_release_workflow_tests_artifacts_outside_source_tree(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "release-rust-python-package.yaml"
        ).read_text()
        preflight_section = self._extract_workflow_job_section(workflow, "preflight")
        build_wheel_section = self._extract_workflow_job_section(workflow, "build-wheel")
        self.assertIn("preflight:", workflow)
        self.assertIn("needs: [resolve, preflight]", workflow)
        self.assertIn("shell: bash", workflow)
        self.assertIn("rustc --version", workflow)
        self.assertIn("working-directory: ${{ needs.resolve.outputs.plugin_path }}", workflow)
        self.assertIn(
            'if [[ -d "${GITHUB_WORKSPACE}/${{ needs.resolve.outputs.plugin_path }}/tests" ]]; then',
            workflow,
        )
        self.assertIn(
            'cp -R "${GITHUB_WORKSPACE}/${{ needs.resolve.outputs.plugin_path }}/tests"',
            workflow,
        )
        self.assertIn('cd "${tmpdir}"', workflow)
        self.assertIn('printf "[pytest]\\npythonpath = tests\\nasyncio_mode = auto\\n" > "${tmpdir}/pytest.ini"', workflow)
        self.assertNotIn('PYTHONPATH="${GITHUB_WORKSPACE}/${{ needs.resolve.outputs.plugin_path }}/tests"', workflow)
        self.assertEqual(workflow.count("cargo run --bin stub_gen"), 1)
        self.assertIn('git show-ref --verify --quiet "refs/tags/${tag}"', workflow)
        self.assertIn("python3 tools/plugin_catalog.py release-info .", workflow)
        self.assertIn('if [[ -n "${TAG_INPUT}" ]]; then', workflow)
        self.assertIn("workflow_call:", workflow)
        self.assertIn("publish_enabled:", workflow)
        self.assertIn('default: false', workflow)
        self.assertIn('git fetch --force origin "refs/heads/main:refs/remotes/origin/main"', workflow)
        self.assertIn('if git merge-base --is-ancestor "${tag_ref}" "refs/remotes/origin/main"; then', workflow)
        self.assertIn("tag_on_main: ${{ steps.resolve.outputs.tag_on_main }}", workflow)
        self.assertIn(
            'wheel_matrix="$(python3 -c \'import json; print(json.dumps([{',
            workflow,
        )
        self.assertIn(
            '{"runner":"ubuntu-24.04-s390x","platform":"linux-s390x"}',
            workflow,
        )
        self.assertIn(
            '{"runner":"ubuntu-24.04-ppc64le","platform":"linux-ppc64le"}',
            workflow,
        )
        self.assertIn(
            'wheel_matrix="$(printf \'%s\' "${release_info}" | python3 -c \'import json, sys; print(json.dumps(json.load(sys.stdin)["release_wheel_matrix"]))\')"',
            workflow,
        )
        self.assertIn("wheel_matrix: ${{ steps.resolve.outputs.wheel_matrix }}", workflow)
        self.assertIn("matrix:\n        include: ${{ fromJson(needs.resolve.outputs.wheel_matrix) }}", workflow)
        self.assertIn("runs-on: ${{ matrix.runner }}", workflow)
        self.assertIn("name: wheel-${{ matrix.platform }}", workflow)
        self.assertIn(
            "if: ${{ (github.event_name != 'workflow_call' || inputs.publish_enabled) && (needs.resolve.outputs.publish_env != 'pypi' || needs.resolve.outputs.tag_on_main == 'true') }}",
            workflow,
        )
        self.assertNotIn("matrix.", preflight_section)
        self.assertIn(
            "matrix.runner != 'ubuntu-24.04-s390x' && matrix.runner != 'ubuntu-24.04-ppc64le'",
            build_wheel_section,
        )
        self.assertIn(
            "matrix.runner == 'ubuntu-24.04-s390x' || matrix.runner == 'ubuntu-24.04-ppc64le'",
            build_wheel_section,
        )
        self.assertIn(
            "sudo apt-get install -y python3.12 python3.12-dev python3.12-venv python3-pip",
            build_wheel_section,
        )
        self.assertIn(
            'ln -sf "$(which python3.12)" "${python_bin_dir}/python"',
            build_wheel_section,
        )
        self.assertIn("sudo apt-get clean", build_wheel_section)
        self.assertIn("sudo rm -rf /var/lib/apt/lists/*", build_wheel_section)
        self.assertIn('export PATH="${python_bin_dir}:$PATH"', build_wheel_section)
        self.assertNotIn('python -m ensurepip --upgrade', build_wheel_section)
        self.assertIn('python -m pip --version', build_wheel_section)
        self.assertNotIn("python -m pip install --upgrade pip", build_wheel_section)
        self.assertNotIn("tools/plugin_catalog.py release-info-field", workflow)
        self.assertNotIn("python3 - <<'PY'", workflow)
        self.assertIn("uv==0.9.30", workflow)
        self.assertIn("maturin==1.12.6", workflow)
        self.assertNotIn("dtolnay/rust-toolchain", workflow)
        self.assertIn(
            'venv_python="${tmpdir}/venv/Scripts/python.exe"',
            workflow,
        )
        self.assertIn('"${venv_python}" -m pip install', workflow)
        self.assertIn('"${venv_python}" -m pytest', workflow)
        self.assertIn(
            "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
            workflow,
        )
        self.assertIn(
            "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
            workflow,
        )
        self.assertIn(
            "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
            workflow,
        )
        self.assertIn(
            "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093",
            workflow,
        )
        self.assertLess(
            workflow.index("name: Upload wheel artifact"),
            workflow.index("name: Test built wheel in isolated virtualenv"),
        )
        self.assertLess(
            workflow.index("name: Upload sdist artifact"),
            workflow.index("name: Test built sdist in isolated virtualenv"),
        )
        self.assertIn(
            "pypa/gh-action-pypi-publish@ed0c53931b1dc9bd32cbe73a98c7f6766f8a527e",
            workflow,
        )
        self.assertNotIn("actions/checkout@v4", workflow)
        self.assertNotIn("actions/setup-python@v5", workflow)
        self.assertNotIn("actions/upload-artifact@v4", workflow)
        self.assertNotIn("actions/download-artifact@v4", workflow)
        self.assertNotIn("pypa/gh-action-pypi-publish@release/v1", workflow)
        self.assertNotRegex(
            workflow,
            r"defaults:\n\s+run:\n\s+shell: bash\n\s+working-directory: .*\$\{\{",
        )

    def test_top_level_stub_exports_match_runtime_packages(self) -> None:
        pii_stub = (
            REPO_ROOT
            / "plugins"
            / "rust"
            / "python-package"
            / "pii_filter"
            / "cpex_pii_filter"
            / "__init__.pyi"
        ).read_text()
        rate_stub = (
            REPO_ROOT
            / "plugins"
            / "rust"
            / "python-package"
            / "rate_limiter"
            / "cpex_rate_limiter"
            / "__init__.pyi"
        ).read_text()
        self.assertIn("PIIFilterPlugin", pii_stub)
        self.assertIn("PIIDetectorRust", pii_stub)
        self.assertIn("RateLimiterConfig", rate_stub)
        self.assertIn("RateLimiterPlugin", rate_stub)
        self.assertIn("_parse_rate", rate_stub)
        self.assertNotIn("PIIFilterPluginCore", pii_stub)
        self.assertNotIn("RateLimiterPluginCore", rate_stub)

    def test_extension_stubs_match_runtime_extension_exports(self) -> None:
        pii_ext_stub = (
            REPO_ROOT
            / "plugins"
            / "rust"
            / "python-package"
            / "pii_filter"
            / "cpex_pii_filter"
            / "pii_filter_rust"
            / "__init__.pyi"
        ).read_text()
        rate_ext_stub = (
            REPO_ROOT
            / "plugins"
            / "rust"
            / "python-package"
            / "rate_limiter"
            / "cpex_rate_limiter"
            / "rate_limiter_rust"
            / "__init__.pyi"
        ).read_text()
        self.assertIn("PIIFilterPluginCore", pii_ext_stub)
        self.assertIn("RateLimiterPluginCore", rate_ext_stub)
        self.assertIn("compat_default_config", rate_ext_stub)
        self.assertIn("compat_parse_rate", rate_ext_stub)

    def test_pii_filter_has_single_authoritative_extension_stub(self) -> None:
        plugin_dir = (
            REPO_ROOT / "plugins" / "rust" / "python-package" / "pii_filter"
        )
        self.assertTrue(
            (
                plugin_dir
                / "cpex_pii_filter"
                / "pii_filter_rust"
                / "__init__.pyi"
            ).exists()
        )
        self.assertFalse(
            (plugin_dir / "python" / "pii_filter_rust" / "__init__.pyi").exists()
        )

    def test_pii_package_imports_without_mcpgateway(self) -> None:
        plugin_dir = (
            REPO_ROOT / "plugins" / "rust" / "python-package" / "pii_filter"
        )
        result = subprocess.run(
            [
                "python3",
                "-c",
                "import cpex_pii_filter; print(cpex_pii_filter.__name__)",
            ],
            cwd=plugin_dir,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "cpex_pii_filter")

    def test_pii_detector_export_is_available_when_extension_is_built(self) -> None:
        plugin_dir = (
            REPO_ROOT / "plugins" / "rust" / "python-package" / "pii_filter"
        )
        package_dir = plugin_dir / "cpex_pii_filter"
        if not self._source_tree_has_extension(package_dir, "pii_filter_rust"):
            self.skipTest("pii_filter extension is not built in the source tree")

        result = subprocess.run(
            [
                "python3",
                "-c",
                "import cpex_pii_filter; print(hasattr(cpex_pii_filter, 'PIIDetectorRust'))",
            ],
            cwd=plugin_dir,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "True")

    def test_pii_stub_examples_use_canonical_import_path(self) -> None:
        stub_path = (
            REPO_ROOT
            / "plugins"
            / "rust"
            / "python-package"
            / "pii_filter"
            / "cpex_pii_filter"
            / "pii_filter_rust"
            / "__init__.pyi"
        )
        text = stub_path.read_text()
        self.assertIn("from cpex_pii_filter import PIIDetectorRust", text)
        self.assertNotIn("from pii_filter import PIIDetectorRust", text)

    def test_pii_benchmark_script_runs_with_package_surface(self) -> None:
        plugin_dir = (
            REPO_ROOT / "plugins" / "rust" / "python-package" / "pii_filter"
        )
        package_dir = plugin_dir / "cpex_pii_filter"
        if not self._source_tree_has_extension(package_dir, "pii_filter_rust"):
            self.skipTest("pii_filter extension is not built in the source tree")

        env = dict(os.environ)
        existing = env.get("PYTHONPATH")
        plugin_path = str(plugin_dir)
        tests_path = str(plugin_dir / "tests")
        env["PYTHONPATH"] = (
            f"{plugin_path}:{tests_path}:{existing}"
            if existing
            else f"{plugin_path}:{tests_path}"
        )
        result = subprocess.run(
            [
                "python3",
                "benchmarks/compare_pii_filter.py",
                "--iterations",
                "1",
            ],
            cwd=plugin_dir,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ops_per_sec", result.stdout)

    def test_root_plugin_test_uses_plugin_ci_target(self) -> None:
        makefile = (REPO_ROOT / "Makefile").read_text()
        self.assertIn("make ci", makefile)
        self.assertNotIn("make install && make test-all", makefile)

    def test_secrets_detection_keeps_scanner_module_internal(self) -> None:
        lib_rs = (
            REPO_ROOT
            / "plugins"
            / "rust"
            / "python-package"
            / "secrets_detection"
            / "src"
            / "lib.rs"
        ).read_text()
        bench_rs = (
            REPO_ROOT
            / "plugins"
            / "rust"
            / "python-package"
            / "secrets_detection"
            / "benches"
            / "secrets_detection.rs"
        ).read_text()
        self.assertIn("mod scanner;", lib_rs)
        self.assertNotIn("pub mod scanner;", lib_rs)
        self.assertIn("pub use scanner::{detect_and_redact, scan_container};", lib_rs)
        self.assertIn("use secrets_detection_rust::detect_and_redact;", bench_rs)
        self.assertNotIn("use secrets_detection_rust::scanner::detect_and_redact;", bench_rs)


if __name__ == "__main__":
    unittest.main()
