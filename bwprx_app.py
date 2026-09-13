"""Entry point for the tray application (PyInstaller builds this into bwprx.exe)."""

from bwprx.app import main

if __name__ == "__main__":
    raise SystemExit(main())
