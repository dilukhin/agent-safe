import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from agent_safe.adapters.exec_adapter import exec_readonly, exec_risky
from agent_safe.adapters.fs import SafetyError
from agent_safe.adapters.git import git_clean_preview
from agent_safe.adapters.ssh_relay import build_relay_command, ssh_relay_readonly
from agent_safe.adapters.yc import yc_change
from agent_safe.core.journal import Journal


class AdapterTests(unittest.TestCase):
    def test_exec_readonly_runs_readonly_command(self):
        with tempfile.TemporaryDirectory() as td:
            journal = Journal(Path(td))
            rec = exec_readonly([sys.executable, "--version"], journal=journal, channel="local", domain="system", reason="version check")
            self.assertEqual(rec.status.value, "done")
            self.assertEqual(rec.risk.value, "safe")

    def test_exec_readonly_rejects_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            journal = Journal(Path(td))
            with self.assertRaises(SafetyError):
                exec_readonly(["rm", "-rf", "x"], journal=journal, channel="local", domain="fs", reason="bad")

    def test_exec_risky_requires_approval(self):
        with tempfile.TemporaryDirectory() as td:
            journal = Journal(Path(td))
            with self.assertRaises(SafetyError):
                exec_risky(
                    [sys.executable, "-c", "print('would change')"],
                    journal=journal,
                    channel="local",
                    domain="unknown",
                    target="test-target",
                    reason="test",
                    expected_state_json=json.dumps({"ok": True}),
                    rollback_command="echo rollback",
                    approved=False,
                )

    def test_exec_risky_blocks_after_unexpected_verify(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            journal = Journal(root)
            rec = exec_risky(
                [sys.executable, "-c", "print('changed')"],
                journal=journal,
                channel="local",
                domain="unknown",
                target="test-target",
                reason="test unexpected",
                expected_state_json=json.dumps({"marker_exists": True}),
                rollback_command="echo rollback",
                verify_command=f"{sys.executable} -c \"import sys; sys.exit(1)\"",
                approved=True,
            )
            self.assertEqual(rec.status.value, "unexpected")
            self.assertTrue(journal.is_blocked())

    def test_exec_risky_runs_receipt_after_success(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            changed = root / "changed.txt"
            receipt = root / "receipt.txt"
            journal = Journal(root)
            rec = exec_risky(
                [sys.executable, "-c", f"from pathlib import Path; Path({str(changed)!r}).write_text('changed')"],
                journal=journal,
                channel="local",
                domain="fs",
                target=str(changed),
                reason="test receipt",
                expected_state_json=json.dumps({"changed": True, "receipt": True}),
                rollback_command="manual cleanup",
                receipt_command=f"{sys.executable} -c \"from pathlib import Path; Path({str(receipt)!r}).write_text('receipt')\"",
                approved=True,
            )
            self.assertEqual(rec.status.value, "done")
            self.assertTrue(changed.exists())
            self.assertTrue(receipt.exists())
            self.assertEqual(rec.verify_result["receipt_returncode"], 0)
            self.assertIsNotNone(rec.metadata["receipt_exec"])

    def test_git_clean_preview_command_is_allowed_in_git_repo(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            subprocess.run(["git", "init"], cwd=root, check=True, text=True, capture_output=True)
            journal = Journal(root)
            rec = git_clean_preview(journal)
            self.assertIn(rec.status.value, {"done", "failed"})
            self.assertEqual(rec.risk.value, "safe")

    def test_ssh_relay_builds_command(self):
        self.assertEqual(build_relay_command("ssh_relay", "pwd"), ["ssh_relay", "exec", "pwd"])

    def test_ssh_relay_builds_named_risky_command(self):
        self.assertEqual(
            build_relay_command(
                "py ssh_relay.py",
                "touch /tmp/x",
                relay_name="prod",
                risky=True,
                receipt_path="~/.local/state/agent-safe/changes.jsonl",
            ),
            [
                "py",
                "ssh_relay.py",
                "exec",
                "--name",
                "prod",
                "--risky",
                "--receipt-path",
                "~/.local/state/agent-safe/changes.jsonl",
                "touch /tmp/x",
            ],
        )

    def test_ssh_relay_readonly_rejects_remote_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            journal = Journal(Path(td))
            with self.assertRaises(SafetyError):
                ssh_relay_readonly("ssh_relay", "rm -rf /tmp/x", journal=journal, host_label="test", reason="bad")

    def test_yc_change_requires_approval_before_yc_is_invoked(self):
        with tempfile.TemporaryDirectory() as td:
            journal = Journal(Path(td))
            with self.assertRaises(SafetyError):
                yc_change(
                    ["compute", "instance", "stop", "--id", "abc"],
                    journal=journal,
                    target="compute.instance:abc",
                    reason="test",
                    expected_state_json=json.dumps({"status": "STOPPED"}),
                    rollback_command="yc compute instance start --id abc",
                    verify_command=None,
                    approved=False,
                    allow_critical=False,
                )


if __name__ == "__main__":
    unittest.main()
