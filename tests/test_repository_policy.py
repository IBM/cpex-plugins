# Copyright 2026
# SPDX-License-Identifier: Apache-2.0
"""Supply-chain policies that build and catalog validation do not enforce."""

import re
import tomllib
import unittest
from datetime import UTC, date, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


class RepositoryPolicyTests(unittest.TestCase):
    def test_external_workflow_actions_are_pinned_to_commit_shas(self) -> None:
        for workflow in (REPO_ROOT / ".github/workflows").glob("*.y*ml"):
            for number, line in enumerate(workflow.read_text().splitlines(), 1):
                match = re.match(r"^\s*-?\s*uses:\s+(\S+)", line)
                if match is None:
                    continue
                reference = match[1].strip("\"'")
                if reference.startswith("./"):
                    continue
                with self.subTest(workflow=workflow.name, line=number):
                    self.assertRegex(reference, r"^[^@]+@[0-9a-f]{40}$")

    def test_cargo_advisory_exceptions_have_not_expired(self) -> None:
        config = tomllib.loads((REPO_ROOT / "deny.toml").read_text())
        for entry in config.get("advisories", {}).get("ignore", []):
            if not isinstance(entry, dict):
                continue
            match = re.search(r"expires (\d{4}-\d{2}-\d{2})", entry.get("reason", ""))
            if match:
                with self.subTest(advisory=entry.get("id")):
                    self.assertLessEqual(datetime.now(UTC).date(), date.fromisoformat(match[1]))
