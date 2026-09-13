"""Where bwprx keeps its files, and how it locks them down."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


def state_dir() -> Path:
    """Per-user directory for config, runtime handshake file and the audit log."""
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~/.local/share")
    d = Path(base) / "bwprx"
    d.mkdir(parents=True, exist_ok=True)
    return d


def config_path() -> Path:
    return state_dir() / "config.json"


def runtime_path() -> Path:
    """Holds the loopback port and the API token. Read by the client."""
    return state_dir() / "runtime.json"


def audit_path() -> Path:
    return state_dir() / "audit.log"


def restrict_to_current_user(path: Path) -> None:
    """Strip inherited ACEs so only this user account can read the file.

    The runtime file carries the API token, which is the only thing standing
    between another local account and the approval API. Best effort: if icacls
    is missing or fails we carry on, because the file still sits under the
    user's own profile.
    """
    if os.name != "nt":
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return

    user = os.environ.get("USERNAME")
    if not user:
        return
    try:
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:(R,W)"],
            capture_output=True,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except OSError:
        pass
