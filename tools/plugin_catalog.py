#!/usr/bin/env python3
"""Plugin discovery and validation for managed Rust Python-package plugins."""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path


MANAGED_ROOT = Path("plugins/rust/python-package")
REPOSITORY_URL = "https://github.com/IBM/cpex-plugins"
SHARED_PATH_PREFIXES = (
    "Makefile",
    ".github/workflows/",
    "Cargo.toml",
    "Cargo.lock",
    "crates/",
    "README.md",
    "DEVELOPING.md",
    "TESTING.md",
    "tests/",
    "tools/",
)

ENTRY_POINT_PATTERN = re.compile(
    r"^(?P<module>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*):(?P<object>[A-Za-z_][A-Za-z0-9_]*)$"
)
MANIFEST_KIND_PATTERN = re.compile(
    r"^(?P<module>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\.(?P<object>[A-Za-z_][A-Za-z0-9_]*)$"
)


class CatalogError(Exception):
    """Raised when managed plugin layout is invalid."""


@dataclass(frozen=True)
class PluginRecord:
    slug: str
    path: str
    package_name: str
    module_name: str
    kind: str
    version: str
    release_wheel_matrix: list[dict[str, str]]


def _release_wheel_matrix() -> list[dict[str, str]]:
    return [
        {"runner": "ubuntu-latest", "platform": "linux-x86_64"},
        {"runner": "ubuntu-24.04-arm", "platform": "linux-aarch64"},
        {"runner": "ubuntu-24.04-s390x", "platform": "linux-s390x"},
        {"runner": "ubuntu-24.04-ppc64le", "platform": "linux-ppc64le"},
        {"runner": "macos-latest", "platform": "macos-arm64"},
        {"runner": "windows-latest", "platform": "windows-x86_64"},
    ]


def _manifest_scalar(manifest_path: Path, key_name: str) -> str:
    value: str | None = None
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        if not line or line[:1].isspace():
            continue
        key, separator, raw_value = line.partition(":")
        if separator != ":":
            continue
        if key.strip() != key_name:
            continue
        raw_candidate = raw_value.strip()
        if raw_candidate[:1] in {'"', "'"}:
            quote = raw_candidate[:1]
            closing_index = raw_candidate.find(quote, 1)
            while closing_index != -1 and raw_candidate[closing_index - 1] == "\\":
                closing_index = raw_candidate.find(quote, closing_index + 1)
            if closing_index == -1:
                candidate = raw_candidate
            else:
                trailing = raw_candidate[closing_index + 1 :].strip()
                if trailing and not trailing.startswith("#"):
                    raise CatalogError(
                        f"Invalid trailing content for {key_name} in {manifest_path}"
                    )
                candidate = ast.literal_eval(raw_candidate[: closing_index + 1])
        else:
            candidate = raw_candidate.split("#", maxsplit=1)[0].strip()
        if not candidate:
            raise CatalogError(f"Empty {key_name} in {manifest_path}")
        if value is not None:
            raise CatalogError(f"Duplicate top-level {key_name} in {manifest_path}")
        value = candidate
    if value is not None:
        return value
    raise CatalogError(f"Missing {key_name} in {manifest_path}")


def _manifest_version(manifest_path: Path) -> str:
    return _manifest_scalar(manifest_path, "version")


def _manifest_kind(manifest_path: Path) -> str:
    return _manifest_scalar(manifest_path, "kind")


def _parse_pyproject(pyproject_path: Path) -> dict:
    try:
        with pyproject_path.open("rb") as handle:
            return tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise CatalogError(f"Invalid TOML in {pyproject_path}: {exc}") from exc


def _parse_cargo(cargo_path: Path) -> dict:
    try:
        with cargo_path.open("rb") as handle:
            return tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise CatalogError(f"Invalid TOML in {cargo_path}: {exc}") from exc


def _expected_package_name(slug: str) -> str:
    return f"cpex-{slug.replace('_', '-')}"


def _expected_module_name(slug: str) -> str:
    return f"cpex_{slug}"


def _expected_maturin_module_name(slug: str) -> str:
    return f"{_expected_module_name(slug)}.{slug}_rust"


def _project_entry_point(pyproject: dict, slug: str) -> str:
    project = pyproject.get("project", {})
    if not isinstance(project, dict):
        raise CatalogError("pyproject.toml [project] must be a table")
    entry_points = project.get("entry-points", {}) if isinstance(project, dict) else {}
    if not isinstance(entry_points, dict):
        raise CatalogError("pyproject.toml project.entry-points must be a table")
    cpex_plugins = entry_points.get("cpex.plugins")
    if not isinstance(cpex_plugins, dict):
        raise CatalogError('pyproject.toml must define [project.entry-points."cpex.plugins"]')
    if any(not isinstance(name, str) or not isinstance(value, str) for name, value in cpex_plugins.items()):
        raise CatalogError('pyproject.toml [project.entry-points."cpex.plugins"] must map plugin names to strings')
    entry_point = cpex_plugins.get(slug)
    if not isinstance(entry_point, str) or not entry_point:
        raise CatalogError(
            f'pyproject.toml must define entry point {slug!r} in [project.entry-points."cpex.plugins"]'
        )
    return entry_point


def _manifest_kind_to_entry_point(value: str, source: str) -> str:
    match = MANIFEST_KIND_PATTERN.fullmatch(value)
    if match is None:
        raise CatalogError(
            f"{source}: kind must use canonical module.object form, got {value}"
        )
    module = match.group("module")
    object_name = match.group("object")
    return f"{module}:{object_name}"


def _validate_entry_point_target(value: str, source: str) -> str:
    if ENTRY_POINT_PATTERN.fullmatch(value) is None:
        raise CatalogError(
            f"{source}: kind must use canonical module:object form, got {value}"
        )
    return value


def discover_plugins(root: Path) -> list[PluginRecord]:
    managed_root = root / MANAGED_ROOT
    if not managed_root.exists():
        raise CatalogError(f"Managed plugin root not found: {managed_root}")

    workspace_members = _workspace_members(root)
    workspace_package = _workspace_package_metadata(root)

    plugins: list[PluginRecord] = []
    for plugin_dir in sorted(path for path in managed_root.iterdir() if path.is_dir()):
        plugins.append(
            validate_plugin_dir(root, plugin_dir, workspace_members, workspace_package)
        )
    _validate_workspace_members(workspace_members, plugins)
    return plugins


def _validate_workspace_members(
    workspace_members: set[str], plugins: list[PluginRecord]
) -> None:
    expected_members = {plugin.path for plugin in plugins}
    if not expected_members.issubset(workspace_members):
        missing = sorted(expected_members - workspace_members)
        raise CatalogError(
            f"Workspace members must include all discovered managed plugins: missing {missing}"
        )


def _workspace_members(root: Path) -> set[str]:
    cargo_toml = root / "Cargo.toml"
    if not cargo_toml.exists():
        raise CatalogError(f"Workspace Cargo.toml not found at {cargo_toml}")
    cargo = _parse_cargo(cargo_toml)
    workspace = cargo.get("workspace", {})
    if not isinstance(workspace, dict):
        raise CatalogError("Workspace Cargo.toml must define [workspace] metadata as a table")
    members = workspace.get("members")
    if not isinstance(members, list):
        raise CatalogError("Workspace Cargo.toml must define [workspace].members")
    if any(not isinstance(member, str) for member in members):
        raise CatalogError("Workspace Cargo.toml [workspace].members must contain only strings")
    return set(members)


def _workspace_package_metadata(root: Path) -> dict:
    cargo_toml = root / "Cargo.toml"
    if not cargo_toml.exists():
        raise CatalogError(f"Workspace Cargo.toml not found at {cargo_toml}")
    cargo = _parse_cargo(cargo_toml)
    workspace = cargo.get("workspace", {})
    if not isinstance(workspace, dict):
        raise CatalogError("Workspace Cargo.toml must define [workspace] metadata as a table")
    package = workspace.get("package", {})
    if not isinstance(package, dict):
        raise CatalogError("Workspace Cargo.toml must define [workspace.package] metadata")
    return package


def validate_plugin_dir(
    root: Path,
    plugin_dir: Path,
    workspace_members: set[str],
    workspace_package: dict,
) -> PluginRecord:
    slug = plugin_dir.name
    expected_package_name = _expected_package_name(slug)
    expected_module_name = _expected_module_name(slug)
    module_dir = plugin_dir / expected_module_name
    manifest_path = module_dir / "plugin-manifest.yaml"

    required_paths = (
        plugin_dir / "pyproject.toml",
        plugin_dir / "Cargo.toml",
        plugin_dir / "Makefile",
        plugin_dir / "README.md",
        plugin_dir / "tests",
        module_dir / "__init__.py",
        manifest_path,
    )
    for required in required_paths:
        if not required.exists():
            raise CatalogError(f"{plugin_dir}: missing required path {required.relative_to(root)}")

    pyproject = _parse_pyproject(plugin_dir / "pyproject.toml")
    cargo = _parse_cargo(plugin_dir / "Cargo.toml")

    project = pyproject.get("project", {})
    if not isinstance(project, dict):
        raise CatalogError(f"{plugin_dir}: pyproject.toml [project] must be a table")
    tool = pyproject.get("tool", {})
    maturin = tool.get("maturin", {}) if isinstance(tool, dict) else {}
    if not isinstance(maturin, dict):
        raise CatalogError(f"{plugin_dir}: pyproject.toml tool.maturin must be a table")
    package = cargo.get("package", {})
    if not isinstance(package, dict):
        raise CatalogError(f"{plugin_dir}: Cargo.toml [package] must be a table")
    relative_plugin_path = str(plugin_dir.relative_to(root))

    if relative_plugin_path not in workspace_members:
        raise CatalogError(
            f"{plugin_dir}: plugin is missing from the top-level Cargo workspace"
        )

    package_name = project.get("name")
    if package_name != expected_package_name:
        raise CatalogError(
            f"{plugin_dir}: package name must be {expected_package_name}, got {package_name}"
        )

    dynamic = project.get("dynamic", [])
    if not isinstance(dynamic, list) or any(not isinstance(item, str) for item in dynamic):
        raise CatalogError(
            f"{plugin_dir}: pyproject.toml must declare dynamic version sourced from Cargo.toml"
        )
    if "version" not in dynamic or "version" in project:
        raise CatalogError(
            f"{plugin_dir}: pyproject.toml must declare dynamic version sourced from Cargo.toml"
        )

    module_name = maturin.get("module-name")
    expected_maturin_module_name = _expected_maturin_module_name(slug)
    if module_name != expected_maturin_module_name:
        raise CatalogError(
            f"{plugin_dir}: tool.maturin.module-name must be {expected_maturin_module_name}, got {module_name}"
        )

    python_source = maturin.get("python-source")
    if python_source != ".":
        raise CatalogError(
            f"{plugin_dir}: tool.maturin.python-source must be '.', got {python_source}"
        )

    repository = package.get("repository")
    if isinstance(repository, dict) and repository.get("workspace") is True:
        repository = workspace_package.get("repository")
    if repository != REPOSITORY_URL:
        raise CatalogError(
            f"{plugin_dir}: repository metadata must point to {REPOSITORY_URL}, got {repository}"
        )

    version = package.get("version")
    if not isinstance(version, str) or not version:
        raise CatalogError(f"{plugin_dir}: Cargo.toml must define a non-empty package.version")

    manifest_version = _manifest_version(manifest_path)
    if manifest_version != version:
        raise CatalogError(
            f"{plugin_dir}: version mismatch between Cargo.toml ({version}) and plugin-manifest.yaml ({manifest_version})"
        )

    manifest_kind = _manifest_kind(manifest_path)
    manifest_entry_point = _manifest_kind_to_entry_point(manifest_kind, str(manifest_path))
    entry_point = _project_entry_point(pyproject, slug)
    entry_point = _validate_entry_point_target(
        entry_point, f"{plugin_dir / 'pyproject.toml'} entry point {slug!r}"
    )
    if manifest_entry_point != entry_point:
        raise CatalogError(
            f"{plugin_dir}: kind mismatch between plugin-manifest.yaml ({manifest_kind}) and pyproject.toml entry point ({entry_point})"
        )

    return PluginRecord(
        slug=slug,
        path=relative_plugin_path,
        package_name=expected_package_name,
        module_name=expected_module_name,
        kind=manifest_kind,
        version=version,
        release_wheel_matrix=_release_wheel_matrix(),
    )


def _git_changed_paths(root: Path, base: str, head: str) -> list[str]:
    completed = subprocess.run(
        ["git", "diff", "--name-only", base, head],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise CatalogError(completed.stderr.strip() or "git diff failed")
    return [line for line in completed.stdout.splitlines() if line.strip()]


def changed_plugins(root: Path, base: str, head: str) -> list[str]:
    plugins = discover_plugins(root)
    return _changed_plugins_for_records(root, plugins, base, head)


def _changed_plugins_for_records(
    root: Path, plugins: list[PluginRecord], base: str, head: str
) -> list[str]:
    plugin_lookup = {record.slug: record for record in plugins}
    changed_paths = _git_changed_paths(root, base, head)

    if any(
        path == prefix.rstrip("/") or path.startswith(prefix)
        for path in changed_paths
        for prefix in SHARED_PATH_PREFIXES
    ):
        return sorted(plugin_lookup)

    changed: set[str] = set()
    managed_prefix = f"{MANAGED_ROOT.as_posix()}/"
    for path in changed_paths:
        if not path.startswith(managed_prefix):
            continue
        relative = path[len(managed_prefix):]
        slug = relative.split("/", maxsplit=1)[0]
        if slug in plugin_lookup:
            changed.add(slug)
    return sorted(changed)


def ci_selection(root: Path, mode: str, base: str | None = None, head: str | None = None) -> dict:
    plugins = discover_plugins(root)
    if mode == "all":
        selected = sorted(plugin.slug for plugin in plugins)
    else:
        if base is None or head is None:
            raise CatalogError("ci-selection diff mode requires base and head revisions")
        selected = _changed_plugins_for_records(root, plugins, base, head)
    return {"plugins": selected, "has_plugins": bool(selected)}


def release_info(root: Path, tag: str) -> PluginRecord:
    if "-v" not in tag:
        raise CatalogError(f"Release tag must match <slug>-v<version>, got {tag}")
    slug_part, version = tag.rsplit("-v", maxsplit=1)
    slug = slug_part.replace("-", "_")
    plugins = {record.slug: record for record in discover_plugins(root)}
    if slug not in plugins:
        raise CatalogError(f"Release tag {tag} does not map to a managed plugin")
    plugin = plugins[slug]
    canonical_tag = f"{plugin.slug.replace('_', '-')}-v{plugin.version}"
    if slug_part != plugin.slug.replace("_", "-"):
        raise CatalogError(
            f"Release tag must use canonical slug form {plugin.slug.replace('_', '-')}-v<version>, got {tag}"
        )
    if plugin.version != version:
        raise CatalogError(
            f"Release tag version {version} does not match Cargo/plugin manifest version {plugin.version} for {slug}"
        )
    return plugin


def _command_list(root: Path) -> int:
    plugins = discover_plugins(root)
    print(json.dumps({"plugins": [asdict(plugin) for plugin in plugins]}, indent=2))
    return 0


def _command_validate(root: Path) -> int:
    discover_plugins(root)
    print(json.dumps({"status": "ok"}, indent=2))
    return 0


def _command_changed(root: Path, base: str, head: str) -> int:
    plugins = changed_plugins(root, base, head)
    print(json.dumps({"plugins": plugins}, indent=2))
    return 0


def _command_release(root: Path, tag: str) -> int:
    plugin = release_info(root, tag)
    print(json.dumps(asdict(plugin), indent=2))
    return 0


def _command_ci_selection(root: Path, mode: str, base: str | None, head: str | None) -> int:
    payload = ci_selection(root, mode, base, head)
    print(json.dumps(payload, indent=2))
    return 0


def _print_field(value: object) -> int:
    if isinstance(value, bool):
        print(str(value).lower())
    elif isinstance(value, (dict, list)):
        print(json.dumps(value))
    else:
        print(value)
    return 0


def _command_release_field(root: Path, tag: str, field: str) -> int:
    plugin = asdict(release_info(root, tag))
    return _print_field(plugin[field])


def _command_ci_selection_field(
    root: Path, mode: str, base: str | None, head: str | None, field: str
) -> int:
    payload = ci_selection(root, mode, base, head)
    return _print_field(payload[field])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("root", nargs="?", default=".")

    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("root", nargs="?", default=".")

    changed_parser = subparsers.add_parser("changed")
    changed_parser.add_argument("root", nargs="?", default=".")
    changed_parser.add_argument("base")
    changed_parser.add_argument("head")

    release_parser = subparsers.add_parser("release-info")
    release_parser.add_argument("root", nargs="?", default=".")
    release_parser.add_argument("tag")

    release_field_parser = subparsers.add_parser("release-info-field")
    release_field_parser.add_argument("root", nargs="?", default=".")
    release_field_parser.add_argument("tag")
    release_field_parser.add_argument(
        "field",
        choices=(
            "slug",
            "path",
            "package_name",
            "module_name",
            "kind",
            "version",
            "release_wheel_matrix",
        ),
    )

    ci_parser = subparsers.add_parser("ci-selection")
    ci_parser.add_argument("root", nargs="?", default=".")
    ci_parser.add_argument("mode", choices=("all", "diff"))
    ci_parser.add_argument("base", nargs="?")
    ci_parser.add_argument("head", nargs="?")

    ci_field_parser = subparsers.add_parser("ci-selection-field")
    ci_field_parser.add_argument("root", nargs="?", default=".")
    ci_field_parser.add_argument("mode", choices=("all", "diff"))
    ci_field_parser.add_argument("base", nargs="?")
    ci_field_parser.add_argument("head", nargs="?")
    ci_field_parser.add_argument("field", choices=("plugins", "has_plugins"))

    return parser


def main() -> int:
    args = build_parser().parse_args()
    root = Path(args.root).resolve()

    try:
        if args.command == "list":
            return _command_list(root)
        if args.command == "validate":
            return _command_validate(root)
        if args.command == "changed":
            return _command_changed(root, args.base, args.head)
        if args.command == "release-info":
            return _command_release(root, args.tag)
        if args.command == "release-info-field":
            return _command_release_field(root, args.tag, args.field)
        if args.command == "ci-selection":
            return _command_ci_selection(root, args.mode, args.base, args.head)
        if args.command == "ci-selection-field":
            return _command_ci_selection_field(root, args.mode, args.base, args.head, args.field)
    except CatalogError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    raise AssertionError(f"Unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
