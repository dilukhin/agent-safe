from __future__ import annotations

import re

from . import __version__
from ._build_metadata import SOURCE_COMMIT

TOOL_LABEL = "agent-safe"
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def source_commit() -> str | None:
    if SOURCE_COMMIT is None:
        return None
    commit = SOURCE_COMMIT.lower()
    return commit if _SHA_RE.fullmatch(commit) else None


def diagnostic_identity() -> str:
    commit = source_commit()
    suffix = commit[:8] if commit is not None else "unknown"
    return f"{TOOL_LABEL} {__version__}.{suffix}"
