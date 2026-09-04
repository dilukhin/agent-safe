from __future__ import annotations

import os
import shutil
import sys
import tempfile
import zipapp
from pathlib import Path

from build_support import resolve_source_commit

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
DIST = ROOT / "dist"
OUT = DIST / "safe.pyz"


def _configure_windows_stdout_utf8() -> None:
    if os.name != "nt":
        return
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if callable(reconfigure):
        reconfigure(encoding="utf-8")


_configure_windows_stdout_utf8()

DIST.mkdir(exist_ok=True)
if OUT.exists():
    OUT.unlink()

source_commit = resolve_source_commit(ROOT)
with tempfile.TemporaryDirectory() as td:
    app_root = Path(td) / "app"
    shutil.copytree(
        SRC,
        app_root,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.egg-info"),
    )
    metadata_path = app_root / "agent_safe" / "_build_metadata.py"
    metadata_path.write_text(
        '"""Сгенерированные метаданные исходной сборки."""\n\n'
        f"SOURCE_COMMIT = {source_commit!r}\n",
        encoding="utf-8",
    )
    zipapp.create_archive(
        app_root,
        OUT,
        main="agent_safe.entrypoint:main",
        interpreter="/usr/bin/env python3",
        compressed=True,
    )

print(f"Создан {OUT}")
