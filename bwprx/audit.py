"""Append-only record of every request and what was decided.

Secrets never reach this file. Only *which* item was asked for, by whom, and
the decision.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict

from . import config
from .paths import audit_path

_lock = threading.Lock()
_listeners: list = []


def subscribe(fn) -> None:
    """Register a callback for live events (used by the tray's recent list)."""
    _listeners.append(fn)


def record(event: str, **fields: Any) -> Dict[str, Any]:
    entry = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "event": event}
    entry.update({k: v for k, v in fields.items() if v is not None})
    line = " | ".join(f"{k}={v}" for k, v in entry.items())

    with _lock:
        p = audit_path()
        try:
            limit = int(config.get("audit_max_bytes"))
            if p.exists() and p.stat().st_size > limit:
                old = p.with_suffix(".log.1")
                old.unlink(missing_ok=True)
                p.rename(old)
        except OSError:
            pass
        try:
            with p.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass

    for fn in list(_listeners):
        try:
            fn(entry)
        except Exception:
            pass
    return entry
