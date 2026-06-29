from __future__ import annotations

import shutil
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
DIST = ROOT / "dist"
OUT = DIST / "safe.pyz"

DIST.mkdir(exist_ok=True)
if OUT.exists():
    OUT.unlink()
zipapp.create_archive(SRC, OUT, main="agent_safe.cli:main", interpreter="/usr/bin/env python3", compressed=True)
print(f"created {OUT}")
