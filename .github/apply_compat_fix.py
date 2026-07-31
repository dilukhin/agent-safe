from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

BASE_COMMIT = "b110a985a449e0b43edd9a34fa03785b301a7c6d"
EXPECTED = {
    "src/agent_safe/__init__.py": "c71212a669c27801b4b1c7a931772c9ca507da77",
    "src/agent_safe/opencode_bootstrap.py": "b63c8485aacac1b6f8a7d87bde1b06eb6603fb33",
    "tests/test_cli.py": "02498dc069a4cc7f86278a78f30deb4a09d1bd33",
    "tests/test_opencode_bootstrap.py": "26eee243c198f18682456cd4b7f03754e85997ff",
}


def blob_sha(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise RuntimeError(f"Неожиданное исходное состояние: {label}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


for filename, expected_sha in EXPECTED.items():
    actual_sha = blob_sha(Path(filename))
    if actual_sha != expected_sha:
        raise RuntimeError(
            f"Неожиданный blob {filename}: {actual_sha} != {expected_sha}"
        )

Path("src/agent_safe/__init__.py").write_text(
    '''"""agent-safe: cross-platform safety runtime for CLI agents."""

import os
import sys


def _configure_windows_stdout_utf8() -> None:
    # Windows может выбрать однобайтовую code page, неспособную вывести русский JSON.
    if os.name != "nt":
        return
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if callable(reconfigure):
        reconfigure(encoding="utf-8")


_configure_windows_stdout_utf8()

__version__ = "0.4.0"
''',
    encoding="utf-8",
)

replace_once(
    Path("src/agent_safe/opencode_bootstrap.py"),
    "from importlib import resources\nfrom importlib.abc import Traversable\n",
    "from importlib import resources\n"
    "try:\n"
    "    from importlib.resources.abc import Traversable\n"
    "except ImportError:  # Python 3.10: Traversable ещё находится в importlib.abc.\n"
    "    from importlib.abc import Traversable\n",
    "импорт Traversable",
)

replace_once(
    Path("tests/test_cli.py"),
    "            text=True,\n            capture_output=True,\n",
    "            encoding=\"utf-8\",\n            capture_output=True,\n",
    "декодирование subprocess в test_cli",
)
replace_once(
    Path("tests/test_cli.py"),
    '\n\nif __name__ == "__main__":\n',
    '''

    @unittest.skipUnless(os.name == "nt", "проверка относится только к Windows")
    def test_bootstrap_json_uses_utf8_on_windows(self):
        with tempfile.TemporaryDirectory() as td:
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "cp1252"
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "agent_safe",
                    "--root",
                    td,
                    "opencode-bootstrap",
                    "--scope",
                    "project",
                    "--dry-run",
                ],
                env=env,
                encoding="utf-8",
                capture_output=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["mode"], "dry-run")
            self.assertIn("Порядок действий", proc.stdout)


if __name__ == "__main__":
''',
    "Windows UTF-8 regression test",
)

replace_once(
    Path("tests/test_opencode_bootstrap.py"),
    "from pathlib import Path\n",
    "from pathlib import Path\n\n"
    "from agent_safe.opencode_bootstrap import _template_root\n",
    "импорт _template_root",
)
replace_once(
    Path("tests/test_opencode_bootstrap.py"),
    "            text=True,\n            capture_output=True,\n",
    "            encoding=\"utf-8\",\n            capture_output=True,\n",
    "декодирование subprocess bootstrap tests",
)
replace_once(
    Path("tests/test_opencode_bootstrap.py"),
    "    def test_opencode_bootstrap_dry_run_does_not_write(self) -> None:\n",
    '''    def test_packaged_template_root_is_available(self) -> None:
        template_root = _template_root()
        self.assertTrue(template_root.joinpath("opencode.json").is_file())
        self.assertTrue(template_root.joinpath("skills").is_dir())

    def test_opencode_bootstrap_dry_run_does_not_write(self) -> None:
''',
    "packaged template regression test",
)

subprocess.run(
    ["git", "checkout", BASE_COMMIT, "--", ".github/workflows/ci.yml"],
    check=True,
)
Path(".github/apply_compat_fix.py").unlink()
