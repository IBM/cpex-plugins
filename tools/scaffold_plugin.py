#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2024 ContextForge Contributors
"""Plugin scaffolding tool for cpex-plugins.

This tool generates a complete plugin structure from templates, including:
- Rust source files (lib.rs, engine.rs, stub_gen.rs)
- Python package files (__init__.py, plugin.py)
- Build configuration (Cargo.toml, pyproject.toml, Makefile)
- Documentation (README.md)
- Test scaffolding

Usage:
    make plugin-scaffold                    # Interactive mode
    python3 tools/scaffold_plugin.py        # Interactive mode
    python3 tools/scaffold_plugin.py --non-interactive --name my_plugin
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
except ImportError:
    print("Error: jinja2 is required. Install with: pip install jinja2", file=sys.stderr)
    sys.exit(1)

# Constants
PLUGIN_ROOT = Path("plugins/rust/python-package")
TEMPLATE_DIR = Path("tools/templates/plugin")
VALID_HOOKS = [
    # Prompt hooks
    "prompt_pre_fetch",
    "prompt_post_fetch",
    # Tool hooks
    "tool_pre_invoke",
    "tool_post_invoke",
    # Resource hooks
    "resource_pre_fetch",
    "resource_post_fetch",
    # Agent hooks
    "agent_pre_invoke",
    "agent_post_invoke",
    # HTTP hooks
    "http_pre_request",
    "http_post_request",
    "http_auth_resolve_user",
    "http_auth_check_permission",
]

# ANSI color codes
GREEN = "\033[0;32m"
YELLOW = "\033[0;33m"
RED = "\033[0;31m"
BLUE = "\033[0;34m"
NC = "\033[0m"  # No Color


class ScaffoldError(Exception):
    """Raised when scaffolding fails."""


class PluginScaffolder:
    """Handles plugin scaffolding operations."""

    def __init__(self, root: Path):
        self.root = root
        self.plugin_root = root / PLUGIN_ROOT
        self.template_dir = root / TEMPLATE_DIR

        if not self.plugin_root.exists():
            raise ScaffoldError(f"Plugin root not found: {self.plugin_root}")

        if not self.template_dir.exists():
            raise ScaffoldError(f"Template directory not found: {self.template_dir}")

        # Setup Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def validate_plugin_name(self, name: str) -> tuple[bool, str]:
        """Validate plugin name format and uniqueness.

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not name:
            return False, "Plugin name cannot be empty"

        if not re.match(r"^[a-z][a-z0-9_]*$", name):
            return False, "Plugin name must be lowercase, start with a letter, and contain only letters, numbers, and underscores"

        if (self.plugin_root / name).exists():
            return False, f"Plugin '{name}' already exists"

        # Check for reserved names
        reserved = {"test", "tests", "plugin", "plugins", "cpex"}
        if name in reserved:
            return False, f"Plugin name '{name}' is reserved"

        return True, ""

    def validate_version(self, version: str) -> tuple[bool, str]:
        """Validate version format (semver)."""
        if not re.match(r"^\d+\.\d+\.\d+$", version):
            return False, "Version must follow semver format (e.g., 0.1.0)"
        return True, ""

    def prompt_for_metadata(self) -> dict[str, Any]:
        """Interactive prompts for plugin metadata."""
        print(f"\n{BLUE}=== CPEX Plugin Scaffold Generator ==={NC}\n")

        # Plugin name
        while True:
            name = input(f"{GREEN}Plugin name{NC} (snake_case, e.g., 'my_plugin'): ").strip()
            is_valid, error = self.validate_plugin_name(name)
            if is_valid:
                break
            print(f"{RED}Error: {error}{NC}")

        # Description
        description = input(f"{GREEN}Description{NC}: ").strip()
        if not description:
            description = f"A CPEX plugin for {name.replace('_', ' ')}"

        # Author
        author = input(f"{GREEN}Author{NC} [ContextForge Contributors]: ").strip()
        if not author:
            author = "ContextForge Contributors"

        # Version
        while True:
            version = input(f"{GREEN}Version{NC} [0.1.0]: ").strip()
            if not version:
                version = "0.1.0"
            is_valid, error = self.validate_version(version)
            if is_valid:
                break
            print(f"{RED}Error: {error}{NC}")

        # Hooks
        print(f"\n{BLUE}Available hooks:{NC}")
        for i, hook in enumerate(VALID_HOOKS, 1):
            print(f"  {i}. {hook}")

        print(f"\n{YELLOW}Enter hook numbers separated by commas (e.g., '1,3,5'){NC}")
        print(f"{YELLOW}Or press Enter to select 'tool_pre_invoke' (default){NC}")

        while True:
            hooks_input = input(f"{GREEN}Hooks{NC}: ").strip()
            if not hooks_input:
                hooks = ["tool_pre_invoke"]
                break

            try:
                indices = [int(x.strip()) for x in hooks_input.split(",")]
                if all(1 <= i <= len(VALID_HOOKS) for i in indices):
                    hooks = [VALID_HOOKS[i - 1] for i in indices]
                    break
                print(f"{RED}Error: Invalid hook numbers{NC}")
            except ValueError:
                print(f"{RED}Error: Please enter numbers separated by commas{NC}")

        # Use framework bridge
        use_bridge = input(f"{GREEN}Use cpex_framework_bridge?{NC} [Y/n]: ").strip().lower()
        use_framework_bridge = use_bridge != "n"

        # Include benchmarks
        include_bench = input(f"{GREEN}Include benchmark scaffolding?{NC} [y/N]: ").strip().lower()
        include_benchmarks = include_bench == "y"

        return {
            "plugin_name": name,
            "description": description,
            "author": author,
            "version": version,
            "hooks": hooks,
            "use_framework_bridge": use_framework_bridge,
            "include_benchmarks": include_benchmarks,
        }

    def derive_metadata(self, metadata: dict[str, Any]) -> dict[str, Any]:
        """Derive additional metadata from user inputs."""
        name = metadata["plugin_name"]

        # Convert snake_case to PascalCase
        pascal = "".join(word.capitalize() for word in name.split("_"))

        # Convert snake_case to Title Case
        title = " ".join(word.capitalize() for word in name.split("_"))

        # Convert snake_case to kebab-case
        slug = name.replace("_", "-")

        derived = {
            **metadata,
            "plugin_name_pascal": pascal,
            "plugin_name_title": title,
            "plugin_slug": slug,
            "package_name": f"cpex-{slug}",
            "module_name": f"cpex_{name}",
            "rust_lib_name": f"{name}_rust",
            "plugin_class": f"{pascal}Plugin",
            "engine_class": f"{pascal}Engine",
            "config_class": f"{pascal}Config",
            # Hook-specific flags
            "has_prompt_hooks": any("prompt" in h for h in metadata["hooks"]),
            "has_tool_hooks": any("tool" in h for h in metadata["hooks"]),
            "has_resource_hooks": any("resource" in h for h in metadata["hooks"]),
        }

        return derived

    def render_templates(self, metadata: dict[str, Any]) -> None:
        """Render all template files."""
        plugin_dir = self.plugin_root / metadata["plugin_name"]
        plugin_dir.mkdir(parents=True, exist_ok=True)

        print(f"\n{BLUE}Generating plugin files...{NC}")

        # Root level files
        root_files = [
            ("Cargo.toml.j2", "Cargo.toml"),
            ("pyproject.toml.j2", "pyproject.toml"),
            ("Makefile.j2", "Makefile"),
            ("README.md.j2", "README.md"),
            ("deny.toml", "deny.toml"),  # Static file, no template
        ]

        for template_name, output_name in root_files:
            if template_name.endswith(".j2"):
                template = self.jinja_env.get_template(template_name)
                content = template.render(**metadata)
            else:
                # Copy static file
                template_path = self.template_dir / template_name
                if template_path.exists():
                    content = template_path.read_text()
                else:
                    continue

            output_path = plugin_dir / output_name
            output_path.write_text(content)
            print(f"  {GREEN}✓{NC} {output_name}")

        # Create empty uv.lock
        (plugin_dir / "uv.lock").touch()
        print(f"  {GREEN}✓{NC} uv.lock")

        # Python package
        module_name = metadata["module_name"]
        module_dir = plugin_dir / module_name
        module_dir.mkdir(exist_ok=True)

        python_files = [
            ("python/__init__.py.j2", "__init__.py"),
            ("python/__init__.pyi.j2", "__init__.pyi"),
            ("python/plugin.py.j2", f"{metadata['plugin_name']}.py"),
            ("plugin-manifest.yaml.j2", "plugin-manifest.yaml"),
        ]

        for template_name, output_name in python_files:
            template = self.jinja_env.get_template(template_name)
            content = template.render(**metadata)
            output_path = module_dir / output_name
            output_path.write_text(content)
            print(f"  {GREEN}✓{NC} {module_name}/{output_name}")

        # Rust module stubs directory
        rust_stub_dir = module_dir / metadata["rust_lib_name"]
        rust_stub_dir.mkdir(exist_ok=True)
        template = self.jinja_env.get_template("python/rust_init.pyi.j2")
        content = template.render(**metadata)
        (rust_stub_dir / "__init__.pyi").write_text(content)
        print(f"  {GREEN}✓{NC} {module_name}/{metadata['rust_lib_name']}/__init__.pyi")

        # Rust source
        src_dir = plugin_dir / "src"
        src_dir.mkdir(exist_ok=True)

        rust_files = [
            ("rust/lib.rs.j2", "lib.rs"),
            ("rust/engine.rs.j2", "engine.rs"),
        ]

        for template_name, output_name in rust_files:
            template = self.jinja_env.get_template(template_name)
            content = template.render(**metadata)
            output_path = src_dir / output_name
            output_path.write_text(content)
            print(f"  {GREEN}✓{NC} src/{output_name}")

        # Stub generator
        bin_dir = src_dir / "bin"
        bin_dir.mkdir(exist_ok=True)
        template = self.jinja_env.get_template("rust/stub_gen.rs.j2")
        content = template.render(**metadata)
        (bin_dir / "stub_gen.rs").write_text(content)
        print(f"  {GREEN}✓{NC} src/bin/stub_gen.rs")

        # Tests
        tests_dir = plugin_dir / "tests"
        tests_dir.mkdir(exist_ok=True)
        template = self.jinja_env.get_template("tests/test_plugin.py.j2")
        content = template.render(**metadata)
        (tests_dir / f"test_{metadata['plugin_name']}.py").write_text(content)
        print(f"  {GREEN}✓{NC} tests/test_{metadata['plugin_name']}.py")

        # Benchmarks (optional)
        if metadata["include_benchmarks"]:
            benches_dir = plugin_dir / "benches"
            benches_dir.mkdir(exist_ok=True)
            template = self.jinja_env.get_template("benches/benchmark.rs.j2")
            content = template.render(**metadata)
            (benches_dir / f"{metadata['plugin_name']}.rs").write_text(content)
            print(f"  {GREEN}✓{NC} benches/{metadata['plugin_name']}.rs")

    def update_workspace(self, plugin_name: str) -> None:
        """Add new plugin to workspace members."""
        cargo_path = self.root / "Cargo.toml"
        new_member = f"plugins/rust/python-package/{plugin_name}"

        print(f"\n{BLUE}Updating workspace Cargo.toml...{NC}")

        # Read current content
        content = cargo_path.read_text()

        # Check if already present
        if new_member in content:
            print(f"  {YELLOW}⚠{NC}  Plugin already in workspace")
            return

        # Find the members array and add the new member
        # Simple approach: find the members section and insert before the closing bracket
        members_pattern = r'(members\s*=\s*\[)(.*?)(\])'

        def add_member(match):
            prefix = match.group(1)
            members = match.group(2)
            suffix = match.group(3)

            # Parse existing members
            member_list = [m.strip().strip('"').strip("'") for m in members.split(",") if m.strip()]
            member_list.append(new_member)
            member_list.sort()

            # Format back
            formatted_members = ",\n    ".join(f'"{m}"' for m in member_list)
            return f'{prefix}\n    {formatted_members},\n{suffix}'

        updated_content = re.sub(members_pattern, add_member, content, flags=re.DOTALL)

        if updated_content != content:
            cargo_path.write_text(updated_content)
            print(f"  {GREEN}✓{NC} Added to workspace members")
        else:
            print(f"  {YELLOW}⚠{NC}  Could not update workspace (manual update required)")

    def print_next_steps(self, metadata: dict[str, Any]) -> None:
        """Print post-generation instructions."""
        name = metadata["plugin_name"]
        plugin_path = f"plugins/rust/python-package/{name}"

        print(f"\n{GREEN}{'=' * 70}{NC}")
        print(f"{GREEN}✅ Plugin '{name}' scaffolded successfully!{NC}")
        print(f"{GREEN}{'=' * 70}{NC}\n")

        print(f"{BLUE}Location:{NC} {plugin_path}\n")

        print(f"{BLUE}Next steps:{NC}\n")
        print(f"1. Review and customize the generated files")
        print(f"   - {YELLOW}src/engine.rs{NC} (Rust core implementation)")
        print(f"   - {YELLOW}{metadata['module_name']}/{name}.py{NC} (Python wrapper)\n")

        print(f"2. Install and test:")
        print(f"   {YELLOW}cd {plugin_path}{NC}")
        print(f"   {YELLOW}make sync{NC}")
        print(f"   {YELLOW}make install{NC}")
        print(f"   {YELLOW}make test-all{NC}\n")

        print(f"3. Run full CI verification:")
        print(f"   {YELLOW}make ci{NC}\n")

        print(f"4. Validate workspace integration:")
        print(f"   {YELLOW}cd ../../../..{NC}")
        print(f"   {YELLOW}make plugins-validate{NC}\n")

        print(f"5. Add to version control:")
        print(f"   {YELLOW}git add {plugin_path}{NC}")
        print(f"   {YELLOW}git commit -s -m 'feat: add {name} plugin scaffold'{NC}\n")

        print(f"{BLUE}Documentation:{NC}")
        print(f"  - Update README.md with your plugin's details")
        print(f"  - Add configuration examples")
        print(f"  - Document hook behavior")
        print(f"  - Add architecture diagrams\n")

        print(f"{BLUE}Reference:{NC}")
        print(f"  - See {YELLOW}plugins/rust/python-package/url_reputation{NC} for a complete example")
        print(f"  - See {YELLOW}DEVELOPING.md{NC} and {YELLOW}TESTING.md{NC} for guidelines\n")

    def generate_plugin(self, metadata: dict[str, Any]) -> None:
        """Main generation workflow."""
        # Derive additional metadata
        full_metadata = self.derive_metadata(metadata)

        # Validate plugin name
        is_valid, error = self.validate_plugin_name(full_metadata["plugin_name"])
        if not is_valid:
            raise ScaffoldError(error)

        # Render templates
        self.render_templates(full_metadata)

        # Update workspace
        self.update_workspace(full_metadata["plugin_name"])

        # Print next steps
        self.print_next_steps(full_metadata)


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Scaffold a new CPEX plugin",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode
  python3 tools/scaffold_plugin.py

  # Non-interactive mode
  python3 tools/scaffold_plugin.py --non-interactive \\
    --name my_plugin \\
    --description "My custom plugin" \\
    --author "John Doe"
        """,
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Use defaults without prompts",
    )
    parser.add_argument("--name", help="Plugin name (snake_case)")
    parser.add_argument("--description", help="Plugin description")
    parser.add_argument("--author", help="Author name")
    parser.add_argument("--version", help="Initial version (default: 0.1.0)")
    parser.add_argument(
        "--hooks",
        help="Comma-separated list of hooks (default: tool_pre_invoke)",
    )
    parser.add_argument(
        "--no-framework-bridge",
        action="store_true",
        help="Do not use cpex_framework_bridge",
    )
    parser.add_argument(
        "--benchmarks",
        action="store_true",
        help="Include benchmark scaffolding",
    )

    args = parser.parse_args()

    try:
        scaffolder = PluginScaffolder(Path.cwd())

        if args.non_interactive:
            if not args.name:
                print(f"{RED}Error: --name is required in non-interactive mode{NC}", file=sys.stderr)
                return 1

            metadata = {
                "plugin_name": args.name,
                "description": args.description or f"A CPEX plugin for {args.name.replace('_', ' ')}",
                "author": args.author or "ContextForge Contributors",
                "version": args.version or "0.1.0",
                "hooks": args.hooks.split(",") if args.hooks else ["tool_pre_invoke"],
                "use_framework_bridge": not args.no_framework_bridge,
                "include_benchmarks": args.benchmarks,
            }
        else:
            metadata = scaffolder.prompt_for_metadata()

        scaffolder.generate_plugin(metadata)
        return 0

    except ScaffoldError as exc:
        print(f"{RED}Error: {exc}{NC}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Cancelled by user{NC}")
        return 130
    except Exception as exc:
        print(f"{RED}Unexpected error: {exc}{NC}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
