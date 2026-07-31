import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


def command_text(*args: str) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline(args)
    return shlex.join(args)


class CliTests(unittest.TestCase):
    def run_cli(self, *args, cwd=None):
        return subprocess.run(
            [sys.executable, "-m", "agent_safe", *args],
            cwd=cwd,
            text=True,
            capture_output=True,
        )

    def test_assess_cli(self):
        proc = self.run_cli("assess", "--command", "rm -rf x")
        self.assertEqual(proc.returncode, 1)
        data = json.loads(proc.stdout)
        self.assertEqual(data["risk"], "critical")

    def test_status_cli(self):
        with tempfile.TemporaryDirectory() as td:
            proc = self.run_cli("--root", td, "status")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            data = json.loads(proc.stdout)
            self.assertFalse(data["blocked"])

    def test_exec_risky_accepts_expected_state_file(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            expected = root / "expected.json"
            expected.write_text(
                '{"assertions":{"ok":true},"declarations":{"operation":"test"}}',
                encoding="utf-8",
            )
            verify = root / "verify.py"
            verify.write_text(
                "import json\nprint(json.dumps({'ok': True}))\n",
                encoding="utf-8",
            )
            proc = self.run_cli(
                "--root", td,
                "exec-risky",
                "--channel", "local",
                "--domain", "unknown",
                "--target", "test-target",
                "--reason", "test file args",
                "--expected-state-file", str(expected),
                "--rollback-command", "manual rollback",
                "--verify-command", command_text(sys.executable, str(verify)),
                "--approved",
                "--", sys.executable, "-c", "print('changed')",
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            data = json.loads(proc.stdout)
            self.assertEqual(data["expected_state"], {
                "assertions": {"ok": True},
                "declarations": {"operation": "test"},
            })
            self.assertTrue(data["verification_complete"])

    def test_receipt_command_prints_posix_jsonl_append(self):
        proc = self.run_cli(
            "receipt-command",
            "--format", "posix",
            "--path", "~/.local/state/agent-safe/changes.jsonl",
            "--change", "install package",
            "--target", "host:prod",
            "--field", "package=nginx",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('"$HOME"/', proc.stdout)
        self.assertIn('"change":"install package"', proc.stdout)
        self.assertIn('"package":"nginx"', proc.stdout)


if __name__ == "__main__":
    unittest.main()
