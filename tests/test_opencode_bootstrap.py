from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class OpenCodeBootstrapTests(unittest.TestCase):
    def run_safe(self, root: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "agent_safe.cli", "--root", str(root), *args],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_opencode_bootstrap_dry_run_does_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc = self.run_safe(root, "opencode-bootstrap", "--scope", "project", "--dry-run")
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["mode"], "dry-run")
            self.assertTrue(payload["planned_changes"])
            self.assertFalse((root / "opencode.json").exists())
            self.assertFalse((root / "AGENTS.md").exists())

    def test_opencode_bootstrap_apply_writes_config_skills_agents_and_journal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc = self.run_safe(root, "opencode-bootstrap", "--scope", "project", "--apply")
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertIs(payload["applied"], True)
            self.assertTrue(payload["journal_txn_id"])

            config = json.loads((root / "opencode.json").read_text(encoding="utf-8"))
            self.assertEqual(config["permission"]["bash"]["safe *"], "allow")
            self.assertEqual(config["permission"]["bash"]["rm *"], "deny")
            self.assertEqual(config["permission"]["skill"]["*"], "allow")

            self.assertTrue((root / ".opencode" / "skills" / "risk-gate" / "SKILL.md").exists())
            agents = (root / "AGENTS.md").read_text(encoding="utf-8")
            self.assertIn("<!-- agent-safe:start -->", agents)

            journal = root / ".agent-safety" / "actions.jsonl"
            self.assertIn("opencode.bootstrap", journal.read_text(encoding="utf-8"))

    def test_opencode_bootstrap_preserves_existing_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "opencode.json").write_text(
                json.dumps({"permission": {"bash": {"custom *": "allow"}, "edit": "deny"}}, indent=2),
                encoding="utf-8",
            )
            proc = self.run_safe(root, "opencode-bootstrap", "--scope", "project", "--apply", "--no-agents", "--no-skills")
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            config = json.loads((root / "opencode.json").read_text(encoding="utf-8"))
            self.assertEqual(config["permission"]["bash"]["custom *"], "allow")
            self.assertEqual(config["permission"]["bash"]["safe *"], "allow")
            self.assertEqual(config["permission"]["edit"], "deny")

    def test_opencode_bootstrap_second_apply_is_noop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = self.run_safe(root, "opencode-bootstrap", "--scope", "project", "--apply")
            self.assertEqual(first.returncode, 0, first.stderr + first.stdout)
            journal = root / ".agent-safety" / "actions.jsonl"
            before = journal.read_text(encoding="utf-8")

            second = self.run_safe(root, "opencode-bootstrap", "--scope", "project", "--apply")
            self.assertEqual(second.returncode, 0, second.stderr + second.stdout)
            payload = json.loads(second.stdout)
            self.assertEqual(payload["planned_changes"], [])
            self.assertIs(payload["applied"], False)
            self.assertIsNone(payload["journal_txn_id"])
            self.assertEqual(journal.read_text(encoding="utf-8"), before)

    def test_opencode_bootstrap_generates_extended_bash_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc = self.run_safe(root, "opencode-bootstrap", "--scope", "project", "--apply", "--no-agents", "--no-skills")
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            config = json.loads((root / "opencode.json").read_text(encoding="utf-8"))
            bash = config["permission"]["bash"]
            self.assertEqual(config["permission"]["edit"], "ask")
            for key in [
                "erase *",
                "shutdown *",
                "Restart-Computer *",
                "Stop-Computer *",
                "wget *|*sh*",
            ]:
                self.assertEqual(bash[key], "deny")


if __name__ == "__main__":
    unittest.main()
