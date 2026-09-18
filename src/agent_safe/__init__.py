"""agent-safe: cross-platform safety runtime for CLI agents."""

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

from ._build_metadata import SOURCE_COMMIT as __source_commit__
