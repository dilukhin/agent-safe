from __future__ import annotations

import sys
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "scripts"))
from build_support import resolve_source_commit  # noqa: E402


class build_py(_build_py):
    def run(self) -> None:
        source_commit = resolve_source_commit(ROOT)
        super().run()
        target = Path(self.build_lib) / "agent_safe" / "_build_metadata.py"
        target.write_text(
            '"""Сгенерированные метаданные исходной сборки."""\n\n'
            f"SOURCE_COMMIT = {source_commit!r}\n",
            encoding="utf-8",
        )


setup(cmdclass={"build_py": build_py})
