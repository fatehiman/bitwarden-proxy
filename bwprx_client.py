"""Entry point for the CLI client (PyInstaller builds this into bwprx-client.exe)."""

from bwprx.client import main

if __name__ == "__main__":
    raise SystemExit(main())
