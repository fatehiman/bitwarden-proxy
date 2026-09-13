"""Locks the vault when it should be locked.

Two triggers: the idle timer, and the Windows workstation being locked or
suspended. The workstation check uses OpenInputDesktop - when the secure
desktop is up (lock screen, UAC, screensaver with password) the call fails with
access denied. That is dependency-free and needs no window to receive session
messages.
"""

from __future__ import annotations

import ctypes
import os
import threading
import time
from typing import Optional

from . import config
from .vault import Vault

DESKTOP_SWITCHDESKTOP = 0x0100


def workstation_locked() -> Optional[bool]:
    """True/False, or None when the state cannot be determined."""
    if os.name != "nt":
        return None
    try:
        user32 = ctypes.windll.user32
        handle = user32.OpenInputDesktop(0, False, DESKTOP_SWITCHDESKTOP)
        if not handle:
            return True
        user32.CloseDesktop(handle)
        return False
    except Exception:
        return None


class Watchdog:
    def __init__(self, vault: Vault, on_change=None) -> None:
        self.vault = vault
        self.on_change = on_change
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="bwprx-watchdog",
                                        daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            interval = max(2, int(config.get("workstation_poll_seconds")))
            self._stop.wait(interval)
            if self._stop.is_set():
                return
            if not self.vault.is_unlocked:
                continue

            left = self.vault.seconds_left()
            if left is not None and left <= 0:
                self.vault.lock(reason="idle timeout")
                self._changed()
                continue

            if config.get("lock_on_workstation_lock") and workstation_locked() is True:
                self.vault.lock(reason="workstation locked")
                self._changed()

    def _changed(self) -> None:
        if callable(self.on_change):
            try:
                self.on_change()
            except Exception:
                pass
