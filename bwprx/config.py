"""User-editable settings, stored as JSON next to the audit log."""

from __future__ import annotations

import json
import threading
from typing import Any, Dict

from .paths import config_path

# Offered in the approval dialog's "remember for" list. (label, seconds)
READ_REMEMBER_CHOICES = [
    ("Just this once", 0),
    ("1 minute", 60),
    ("5 minutes", 5 * 60),
    ("10 minutes", 10 * 60),
    ("30 minutes", 30 * 60),
    ("1 hour", 60 * 60),
    ("2 hours", 2 * 60 * 60),
    ("3 hours", 3 * 60 * 60),
    ("6 hours", 6 * 60 * 60),
]

# Writes are rare and not reversible, so the list stops at 5 minutes - just
# enough to cover a burst of related writes without leaving a standing licence.
WRITE_REMEMBER_CHOICES = [
    ("Just this once", 0),
    ("1 minute", 60),
    ("5 minutes", 5 * 60),
]

DEFAULTS: Dict[str, Any] = {
    # Vault session
    "idle_timeout_minutes": 360,        # 6h; timer resets on every approved request
    "lock_on_workstation_lock": True,   # lock when Windows locks / sleeps
    "workstation_poll_seconds": 10,
    # Local API
    "port": 7395,                       # loopback only
    # Approval dialog
    "approval_timeout_seconds": 120,    # no answer => denied
    "default_read_remember_seconds": 0,
    "default_write_remember_seconds": 0,
    # Passwords generated on the app's side, so they never reach the agent
    "generate_length": 24,
    # Searching returns titles, usernames and URIs but never secrets. Approving
    # it is still the default, because the list of accounts you hold is itself
    # worth protecting. Set to false if the prompts get in the way.
    "require_approval_for_list": True,
    # Show a tray balloon when a remembered approval is used without a dialog,
    # so silent access is still visible.
    "notify_on_auto_approve": True,
    # Housekeeping
    "audit_max_bytes": 2 * 1024 * 1024,
}

_lock = threading.Lock()
_cache: Dict[str, Any] | None = None


def load(force: bool = False) -> Dict[str, Any]:
    global _cache
    with _lock:
        if _cache is not None and not force:
            return dict(_cache)
        cfg = dict(DEFAULTS)
        p = config_path()
        if p.exists():
            try:
                cfg.update(json.loads(p.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                # A broken config must not stop the app from starting; the
                # defaults are safe.
                pass
        else:
            try:
                p.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
            except OSError:
                pass
        _cache = cfg
        return dict(cfg)


def get(key: str) -> Any:
    return load().get(key, DEFAULTS.get(key))


def set_value(key: str, value: Any) -> None:
    global _cache
    with _lock:
        cfg = dict(_cache) if _cache is not None else dict(DEFAULTS)
        cfg[key] = value
        try:
            config_path().write_text(json.dumps(cfg, indent=2), encoding="utf-8")
        except OSError:
            pass
        _cache = cfg
