import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from agent_safe import __version__
from agent_safe.build_identity import diagnostic_identity


ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA = "0123456789abcdef0123456789abcdef01234567"
EXPECTED_IDENTITY = f"agent-safe {__version__}.{SOURCE_SHA[:8]}"


class BuildIdentityTests(unittest.TestCase):
    def run_source_cli(self, *args: str, cwd: str | None = None) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        return subprocess.run(
            [sys.executable, "-m", "agent_safe", *args],
            cwd=cwd,
            env=env,
            encoding="utf-8",
            capture_output=True,
        )

    def test_semantic_version_matches_package_metadata(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        match = re.search(
            r'(?ms)^\[project\]\s.*?^version\s*=\s*"([^"]+)"',
            text,
        )
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), __version__)

    def test_source_version_command_uses_single_canonical_identity(self):
        proc = self.run_source_cli("--version")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), diagnostic_identity())
        self.assertEqual(proc.stderr, "")

    def test_ordinary_json_stdout_remains_one_json_document(self):
        with tempfile.TemporaryDirectory() as td:
            proc = self.run_source_cli("--root", td, "status")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        json.loads(proc.stdout)
        self.assertEqual(proc.stderr.strip(), diagnostic_identity())
        self.assertEqual(proc.stderr.count(diagnostic_identity()), 1)

    def test_safety_error_keeps_json_stdout_and_single_identity(self):
        with tempfile.TemporaryDirectory() as td:
            proc = self.run_source_cli("--root", td, "undo", "missing-transaction")
        self.assertEqual(proc.returncode, 2, proc.stderr + proc.stdout)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["type"], "SafetyError")
        self.assertEqual(proc.stderr.count(diagnostic_identity()), 1)

    def test_parser_error_has_single_identity(self):
        proc = self.run_source_cli("definitely-not-a-command")
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, "")
        self.assertEqual(proc.stderr.count(diagnostic_identity()), 1)

    def test_installed_runtime_keeps_full_sha_without_git_checkout(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            install_dir = root / "installed"
            runtime_cwd = root / "runtime"
            runtime_cwd.mkdir()

            build_env = os.environ.copy()
            build_env["AGENT_SAFE_SOURCE_COMMIT"] = SOURCE_SHA
            install = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    "--no-deps",
                    "--no-build-isolation",
                    "--target",
                    str(install_dir),
                    str(ROOT),
                ],
                cwd=ROOT,
                env=build_env,
                encoding="utf-8",
                capture_output=True,
            )
            self.assertEqual(install.returncode, 0, install.stderr + install.stdout)

            runtime_env = os.environ.copy()
            runtime_env.pop("AGENT_SAFE_SOURCE_COMMIT", None)
            runtime_env["PYTHONPATH"] = str(install_dir)

            probe = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "import json; "
                        "from agent_safe import __source_commit__, __version__; "
                        "from agent_safe.build_identity import diagnostic_identity; "
                        "print(json.dumps({"
                        "'commit': __source_commit__, "
                        "'version': __version__, "
                        "'identity': diagnostic_identity()"
                        "}))"
                    ),
                ],
                cwd=runtime_cwd,
                env=runtime_env,
                encoding="utf-8",
                capture_output=True,
            )
            self.assertEqual(probe.returncode, 0, probe.stderr + probe.stdout)
            payload = json.loads(probe.stdout)
            self.assertEqual(payload["commit"], SOURCE_SHA)
            self.assertEqual(payload["version"], __version__)
            self.assertEqual(payload["identity"], EXPECTED_IDENTITY)
            self.assertFalse((runtime_cwd / ".git").exists())

            version = subprocess.run(
                [sys.executable, "-m", "agent_safe", "--version"],
                cwd=runtime_cwd,
                env=runtime_env,
                encoding="utf-8",
                capture_output=True,
            )
            self.assertEqual(version.returncode, 0, version.stderr)
            self.assertEqual(version.stdout.strip(), EXPECTED_IDENTITY)
            self.assertEqual(version.stderr, "")

            status = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "agent_safe",
                    "--root",
                    str(runtime_cwd),
                    "status",
                ],
                cwd=runtime_cwd,
                env=runtime_env,
                encoding="utf-8",
                capture_output=True,
            )
            self.assertEqual(status.returncode, 0, status.stderr + status.stdout)
            json.loads(status.stdout)
            self.assertEqual(status.stderr.strip(), EXPECTED_IDENTITY)


if __name__ == "__main__":
    unittest.main()
