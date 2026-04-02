#!/usr/bin/env python3
"""Install a single built wheel from a wheel directory."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import sysconfig
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install the best matching compatible wheel from a wheel directory."
    )
    parser.add_argument("--wheel-dir", required=True, help="Directory containing wheels.")
    parser.add_argument(
        "--wheel-prefix",
        required=True,
        help="Wheel filename prefix, for example cpex_rate_limiter.",
    )
    parser.add_argument(
        "--python",
        help="Python interpreter path to pass to uv pip install.",
    )
    parser.add_argument(
        "--venv-dir",
        help="Virtualenv directory to search for bin/python or Scripts/python.exe.",
    )
    parser.add_argument(
        "--package-name",
        help="Package name for log messages.",
    )
    parser.add_argument(
        "--print-only",
        action="store_true",
        help="Print the selected wheel path without installing it.",
    )
    return parser.parse_args()


def interpreter_tags(python_bin: str) -> dict[str, str]:
    completed = subprocess.run(
        [
            python_bin,
            "-c",
            (
                "import json, platform, sys, sysconfig; "
                "print(json.dumps({"
                "'python_tag': f'cp{sys.version_info[0]}{sys.version_info[1]}', "
                "'platform_tag': sysconfig.get_platform().replace('-', '_').replace('.', '_'), "
                "'system': platform.system().lower(), "
                "'machine': platform.machine().lower().replace('-', '_')"
                "}))"
            ),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "failed to inspect python interpreter")
    return json.loads(completed.stdout)


def current_interpreter_tags() -> dict[str, str]:
    platform_tag = sysconfig.get_platform().replace("-", "_").replace(".", "_")
    return {
        "python_tag": f"cp{sys.version_info[0]}{sys.version_info[1]}",
        "platform_tag": platform_tag,
        "system": sys.platform,
        "machine": platform_tag.split("_")[-1],
    }


def wheel_score(path: Path, wheel_prefix: str, tags: dict[str, str] | None) -> tuple[int, int, str]:
    stem = path.stem
    prefix = f"{wheel_prefix}-"
    if not stem.startswith(prefix):
        return (-1, 0, path.name)

    parts = stem[len(prefix) :].split("-")
    if len(parts) < 3:
        return (-1, 0, path.name)

    python_tag, abi_tag, platform_tag = parts[-3:]
    score = 0
    platform_compatible = tags is None
    if tags is not None:
        python_tags = set(python_tag.split("."))
        if tags["python_tag"] in python_tags:
            score += 6
        elif abi_tag == "abi3" and any(tag.startswith("cp3") for tag in python_tags):
            score += 5
        elif "py3" in python_tags:
            score += 3

        platform_tags = set(platform_tag.split("."))
        current_platform = tags["platform_tag"]
        current_machine = tags["machine"]
        current_system = tags["system"]
        if "any" in platform_tags:
            score += 1
            platform_compatible = True
        elif current_platform in platform_tags:
            score += 6
            platform_compatible = True
        elif current_system.startswith("linux") and any(
            tag.endswith(current_machine) and "linux" in tag for tag in platform_tags
        ):
            score += 5
            platform_compatible = True
        elif current_system == "darwin" and any(
            tag.endswith(current_machine) and tag.startswith("macosx")
            for tag in platform_tags
        ):
            score += 5
            platform_compatible = True
        elif current_system.startswith("win") and any(
            tag.endswith(current_machine) and tag.startswith("win") for tag in platform_tags
        ):
            score += 5
            platform_compatible = True

        if not platform_compatible:
            return (-1, path.stat().st_mtime_ns, path.name)

    return (score, path.stat().st_mtime_ns, path.name)


def select_wheel(
    wheel_dir: Path,
    wheel_prefix: str,
    python_bin: str | None = None,
) -> Path:
    matches = sorted(
        wheel_dir.glob(f"{wheel_prefix}-*.whl"),
        key=lambda path: path.name,
    )
    if not matches:
        raise FileNotFoundError(
            f"No built wheel found for prefix '{wheel_prefix}' in {wheel_dir}"
        )
    tags = interpreter_tags(python_bin) if python_bin else current_interpreter_tags()
    ranked = sorted(matches, key=lambda path: wheel_score(path, wheel_prefix, tags))
    selected = ranked[-1]
    if wheel_score(selected, wheel_prefix, tags)[0] < 0:
        raise FileNotFoundError(
            f"No compatible built wheel found for prefix '{wheel_prefix}' in {wheel_dir}"
        )
    return selected


def install_wheel(python_bin: str, wheel_path: Path) -> int:
    command = [
        "uv",
        "pip",
        "install",
        "--python",
        python_bin,
        "--force-reinstall",
        str(wheel_path),
    ]
    completed = subprocess.run(command, check=False)
    return completed.returncode


def resolve_python_bin(explicit_python: str | None, venv_dir: str | None) -> str | None:
    if explicit_python:
        return explicit_python
    if not venv_dir:
        return None

    venv_path = Path(venv_dir)
    candidates = (
        venv_path / "bin" / "python",
        venv_path / "Scripts" / "python.exe",
        venv_path / "Scripts" / "python",
    )
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return None


def main() -> int:
    args = parse_args()
    python_bin = resolve_python_bin(args.python, args.venv_dir)
    if not args.print_only and not python_bin:
        print("--python is required unless --print-only is used", file=sys.stderr)
        return 2

    try:
        wheel_path = select_wheel(Path(args.wheel_dir), args.wheel_prefix, python_bin)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if args.print_only:
        print(wheel_path)
        return 0

    package_name = args.package_name or args.wheel_prefix
    print(f"Selected wheel for {package_name}: {wheel_path}")
    return install_wheel(python_bin, wheel_path)


if __name__ == "__main__":
    raise SystemExit(main())
