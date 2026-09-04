from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py

ROOT = Path(__file__).resolve().parent
_SOURCE_COMMIT_ENV = "AGENT_SAFE_SOURCE_COMMIT"
_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


def _resolve_source_commit() -> str | None:
    configured = os.environ.get(_SOURCE_COMMIT_ENV)
    if configured is not None:
        commit = configured.strip().lower()
        if not _SHA_RE.fullmatch(commit):
            raise RuntimeError(
                f"{_SOURCE_COMMIT_ENV} должен содержать ровно 40 шестнадцатеричных символов"
            )
        return commit

    try:
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        if status.stdout.strip():
            return None
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None

    commit = result.stdout.strip().lower()
    return commit if _SHA_RE.fullmatch(commit) else None


class build_py(_build_py):
    def run(self) -> None:
        source_commit = _resolve_source_commit()
        super().run()
        target = Path(self.build_lib) / "agent_safe" / "_build_metadata.py"
        target.write_text(
            '"""Сгенерированные метаданные исходной сборки."""\n\n'
            f"SOURCE_COMMIT = {source_commit!r}\n",
            encoding="utf-8",
        )


setup(cmdclass={"build_py": build_py})
