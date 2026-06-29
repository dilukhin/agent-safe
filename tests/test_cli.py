import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class CliTests(unittest.TestCase):
    def run_cli(self, *args, cwd=None):
        return subprocess.run([sys.executable, "-m", "agent_safe", *args], cwd=cwd, text=True, capture_output=True)

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


if __name__ == "__main__":
    unittest.main()
