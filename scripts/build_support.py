from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

_SOURCE_COMMIT_ENV = "AGENT_SAFE_SOURCE_COMMIT"
_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


def resolve_source_commit(root: Path) -> str | None:
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
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
        if status.stdout.strip():
            return None
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None

    commit = result.stdout.strip().lower()
    return commit if _SHA_RE.fullmatch(commit) else None
