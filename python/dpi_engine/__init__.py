"""
Kernel-Bypass DPI Streamer (C++20 / Python)
High-performance zero-copy network sniffer and DPI inspection engine.
"""

import os
import sys
from pathlib import Path

if sys.platform == "win32":
    pkg_dir = Path(__file__).resolve().parent
    search_dirs = [
        pkg_dir,
        pkg_dir / "Release",
        pkg_dir.parent.parent / "build" / "Release",
        pkg_dir.parent.parent,
    ]
    for d in search_dirs:
        if d.exists() and str(d) not in sys.path:
            sys.path.insert(0, str(d))
        if (d / "WinDivert.dll").exists():
            try:
                os.add_dll_directory(str(d))
            except (AttributeError, OSError):
                pass
            os.environ["PATH"] = str(d) + os.pathsep + os.environ.get("PATH", "")

from .sniffer import SnifferStream
from .filters import DpiFilter, Proto

__all__ = ["SnifferStream", "DpiFilter", "Proto"]
