"""Build both executables with PyInstaller.

    python build.py            # build both
    python build.py app        # tray app only
    python build.py client     # client only

Output lands in dist/:
    bwprx.exe          windowed tray app (no console window)
    bwprx-client.exe   console client for agents and scripts
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
BUILD = ROOT / "build"

COMMON = [
    "--noconfirm",
    "--clean",
    "--onefile",
    "--distpath", str(DIST),
    "--workpath", str(BUILD),
    "--specpath", str(BUILD),
    "--paths", str(ROOT),
]

TARGETS = {
    "app": {
        "script": "bwprx_app.py",
        "name": "bwprx",
        # No console: this is a tray app. Its dialogs are Tk windows.
        "extra": ["--windowed",
                  "--hidden-import", "pystray._win32",
                  "--hidden-import", "PIL._tkinter_finder"],
    },
    "client": {
        "script": "bwprx_client.py",
        "name": "bwprx-client",
        # Console: agents read its stdout.
        "extra": ["--console",
                  "--exclude-module", "pystray",
                  "--exclude-module", "tkinter"],
    },
}


def build(target: str) -> int:
    spec = TARGETS[target]
    cmd = [sys.executable, "-m", "PyInstaller", *COMMON,
           "--name", spec["name"], *spec["extra"], str(ROOT / spec["script"])]
    print("=" * 70)
    print(f"building {spec['name']}.exe")
    print("=" * 70)
    return subprocess.call(cmd, cwd=str(ROOT))


def main(argv: list[str]) -> int:
    wanted = argv[1:] or list(TARGETS)
    for name in wanted:
        if name not in TARGETS:
            print(f"unknown target {name!r}; choose from {', '.join(TARGETS)}")
            return 2
    for name in wanted:
        rc = build(name)
        if rc != 0:
            print(f"FAILED: {name} (exit {rc})")
            return rc
    shutil.rmtree(BUILD, ignore_errors=True)
    print()
    print("built:")
    for exe in sorted(DIST.glob("*.exe")):
        print(f"  {exe}  ({exe.stat().st_size / 1_048_576:.1f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
