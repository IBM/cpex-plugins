import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "tools" / "install_built_wheel.py"
SPEC = importlib.util.spec_from_file_location("install_built_wheel", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def run_install_built_wheel(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["python3", str(SCRIPT), *args],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


class InstallBuiltWheelTests(unittest.TestCase):
    def test_help_describes_compatibility_aware_selection(self) -> None:
        result = run_install_built_wheel("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("best matching compatible wheel", result.stdout)

    def test_prints_only_matching_wheel_when_multiple_exist(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wheel_dir = Path(tmpdir)
            older = wheel_dir / "cpex_rate_limiter-0.0.2-cp311-abi3-linux_x86_64.whl"
            newer = wheel_dir / "cpex_rate_limiter-0.0.2-cp311-abi3-manylinux_2_34_x86_64.whl"
            other = wheel_dir / "cpex_pii_filter-0.1.0-cp311-abi3-manylinux_2_34_x86_64.whl"
            older.write_text("")
            newer.write_text("")
            other.write_text("")
            older_mtime = older.stat().st_mtime_ns
            newer_mtime = older_mtime + 1_000_000
            other_mtime = newer_mtime + 1_000_000
            os.utime(older, ns=(older_mtime, older_mtime))
            os.utime(newer, ns=(newer_mtime, newer_mtime))
            os.utime(other, ns=(other_mtime, other_mtime))

            with patch.object(
                MODULE,
                "current_interpreter_tags",
                return_value={
                    "python_tag": "cp311",
                    "platform_tag": "linux_x86_64",
                    "system": "linux",
                    "machine": "x86_64",
                },
            ):
                selected = MODULE.select_wheel(wheel_dir, "cpex_rate_limiter")

            self.assertEqual(selected, older)

    def test_select_wheel_prefers_compatible_platform_over_newer_incompatible_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wheel_dir = Path(tmpdir)
            compatible = wheel_dir / "cpex_rate_limiter-0.0.2-cp311-abi3-manylinux_2_34_x86_64.whl"
            incompatible = wheel_dir / "cpex_rate_limiter-0.0.2-cp311-abi3-macosx_11_0_arm64.whl"
            compatible.write_text("")
            incompatible.write_text("")
            compatible_mtime = compatible.stat().st_mtime_ns
            incompatible_mtime = compatible_mtime + 1_000_000
            os.utime(compatible, ns=(compatible_mtime, compatible_mtime))
            os.utime(incompatible, ns=(incompatible_mtime, incompatible_mtime))

            with patch.object(
                MODULE,
                "current_interpreter_tags",
                return_value={
                    "python_tag": "cp311",
                    "platform_tag": "linux_x86_64",
                    "system": "linux",
                    "machine": "x86_64",
                },
            ):
                selected = MODULE.select_wheel(wheel_dir, "cpex_rate_limiter")

            self.assertEqual(selected, compatible)

    def test_errors_when_only_incompatible_wheels_exist(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wheel_dir = Path(tmpdir)
            incompatible = wheel_dir / "cpex_rate_limiter-0.0.2-cp311-abi3-macosx_11_0_arm64.whl"
            incompatible.write_text("")

            with patch.object(
                MODULE,
                "current_interpreter_tags",
                return_value={
                    "python_tag": "cp311",
                    "platform_tag": "linux_x86_64",
                    "system": "linux",
                    "machine": "x86_64",
                },
            ):
                with self.assertRaises(FileNotFoundError):
                    MODULE.select_wheel(wheel_dir, "cpex_rate_limiter")

    def test_select_wheel_matches_macos_platforms(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wheel_dir = Path(tmpdir)
            compatible = wheel_dir / "cpex_rate_limiter-0.0.2-cp311-abi3-macosx_11_0_arm64.whl"
            incompatible = wheel_dir / "cpex_rate_limiter-0.0.2-cp311-abi3-win_amd64.whl"
            compatible.write_text("")
            incompatible.write_text("")

            with patch.object(
                MODULE,
                "current_interpreter_tags",
                return_value={
                    "python_tag": "cp311",
                    "platform_tag": "macosx_11_0_arm64",
                    "system": "darwin",
                    "machine": "arm64",
                },
            ):
                selected = MODULE.select_wheel(wheel_dir, "cpex_rate_limiter")

            self.assertEqual(selected, compatible)

    def test_select_wheel_matches_windows_platforms(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wheel_dir = Path(tmpdir)
            compatible = wheel_dir / "cpex_rate_limiter-0.0.2-cp311-abi3-win_amd64.whl"
            incompatible = wheel_dir / "cpex_rate_limiter-0.0.2-cp311-abi3-macosx_11_0_arm64.whl"
            compatible.write_text("")
            incompatible.write_text("")

            with patch.object(
                MODULE,
                "current_interpreter_tags",
                return_value={
                    "python_tag": "cp311",
                    "platform_tag": "win_amd64",
                    "system": "win32",
                    "machine": "amd64",
                },
            ):
                selected = MODULE.select_wheel(wheel_dir, "cpex_rate_limiter")

            self.assertEqual(selected, compatible)

    def test_errors_when_no_matching_wheel_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wheel_dir = Path(tmpdir)
            result = run_install_built_wheel(
                "--wheel-dir",
                str(wheel_dir),
                "--wheel-prefix",
                "cpex_rate_limiter",
                "--print-only",
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("No built wheel found", result.stderr)

    def test_errors_when_install_requested_without_python_or_venv(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wheel_dir = Path(tmpdir)
            (wheel_dir / "cpex_rate_limiter-0.0.2-py3-none-any.whl").write_text("")
            result = run_install_built_wheel(
                "--wheel-dir",
                str(wheel_dir),
                "--wheel-prefix",
                "cpex_rate_limiter",
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("--python is required", result.stderr)

    def test_print_only_succeeds_without_python_or_venv(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wheel_dir = Path(tmpdir)
            wheel = wheel_dir / "cpex_rate_limiter-0.0.2-py3-none-any.whl"
            wheel.write_text("")

            result = run_install_built_wheel(
                "--wheel-dir",
                str(wheel_dir),
                "--wheel-prefix",
                "cpex_rate_limiter",
                "--print-only",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), str(wheel))

    def test_resolves_windows_venv_python(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            venv_python = root / ".venv" / "Scripts" / "python.exe"
            venv_python.parent.mkdir(parents=True)
            venv_python.write_text("")

            self.assertEqual(
                MODULE.resolve_python_bin(None, str(root / ".venv")),
                str(venv_python),
            )

    def test_resolves_unix_venv_python(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            venv_python = root / ".venv" / "bin" / "python"
            venv_python.parent.mkdir(parents=True)
            venv_python.write_text("")

            self.assertEqual(
                MODULE.resolve_python_bin(None, str(root / ".venv")),
                str(venv_python),
            )

    def test_install_wheel_invokes_uv_with_selected_python(self) -> None:
        wheel = Path("/tmp/example.whl")
        with patch.object(MODULE.subprocess, "run") as run_mock:
            run_mock.return_value = subprocess.CompletedProcess(args=[], returncode=0)
            result = MODULE.install_wheel("C:/venv/Scripts/python.exe", wheel)

        self.assertEqual(result, 0)
        run_mock.assert_called_once_with(
            [
                "uv",
                "pip",
                "install",
                "--python",
                "C:/venv/Scripts/python.exe",
                "--force-reinstall",
                str(wheel),
            ],
            check=False,
        )

    def test_main_installs_selected_wheel_via_resolved_venv(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wheel_dir = Path(tmpdir)
            wheel = wheel_dir / "cpex_rate_limiter-0.0.2-cp311-abi3-manylinux_2_34_x86_64.whl"
            wheel.write_text("")
            venv_python = wheel_dir / ".venv" / "bin" / "python"
            venv_python.parent.mkdir(parents=True)
            venv_python.write_text("")

            with patch.object(MODULE, "interpreter_tags") as interpreter_tags_mock, patch.object(
                MODULE, "install_wheel", return_value=0
            ) as install_mock, patch.object(sys, "argv", [
                "install_built_wheel.py",
                "--wheel-dir",
                str(wheel_dir),
                "--wheel-prefix",
                "cpex_rate_limiter",
                "--venv-dir",
                str(wheel_dir / ".venv"),
                "--package-name",
                "cpex-rate-limiter",
            ]):
                interpreter_tags_mock.return_value = {
                    "python_tag": "cp311",
                    "platform_tag": "linux_x86_64",
                    "system": "linux",
                    "machine": "x86_64",
                }
                result = MODULE.main()

            self.assertEqual(result, 0)
            install_mock.assert_called_once_with(str(venv_python), wheel)


if __name__ == "__main__":
    unittest.main()
