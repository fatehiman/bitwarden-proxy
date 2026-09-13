"""Tray application entry point."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from typing import Optional

import pystray

from . import audit, config, icon as icon_mod
from .broker import Broker, Denied
from .paths import audit_path, config_path
from .server import ApiServer
from .ui import UiService
from .vault import Vault, VaultError
from .watchdog import Watchdog

APP_NAME = "bwprx"


class TrayApp:
    def __init__(self) -> None:
        config.load()
        self.vault = Vault()
        self.ui = UiService()
        self.broker = Broker(self.vault, self.ui)
        self.api: Optional[ApiServer] = None
        self.watchdog = Watchdog(self.vault, on_change=self._refresh)
        self.icon: Optional[pystray.Icon] = None
        self._refresh_thread: Optional[threading.Thread] = None
        self._stopping = threading.Event()

    # ------------------------------------------------------------------ menu

    def _status_text(self) -> str:
        if not self.vault.bw_path:
            return "Bitwarden CLI not found"
        if not self.vault.is_unlocked:
            cli = self.vault.cli_status().get("status")
            if cli == "unauthenticated":
                return "Not logged in - run `bw login`"
            return "Vault locked"
        left = self.vault.seconds_left() or 0
        mins = left // 60
        if mins >= 60:
            return f"Unlocked - locks in {mins // 60}h {mins % 60}m idle"
        return f"Unlocked - locks in {mins}m idle"

    def _grants_text(self) -> str:
        n = len(self.broker.cache.active())
        return f"Forget remembered approvals ({n})" if n else "No remembered approvals"

    def _build_menu(self) -> pystray.Menu:
        return pystray.Menu(
            pystray.MenuItem(lambda _i: self._status_text(), None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Unlock vault...", self._on_unlock,
                             visible=lambda _i: not self.vault.is_unlocked),
            pystray.MenuItem("Lock now", self._on_lock,
                             visible=lambda _i: self.vault.is_unlocked),
            pystray.MenuItem(lambda _i: self._grants_text(), self._on_forget,
                             enabled=lambda _i: bool(self.broker.cache.active())),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Open activity log", self._on_open_log),
            pystray.MenuItem("Open settings file", self._on_open_config),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", self._on_quit),
        )

    # --------------------------------------------------------------- actions

    def _on_unlock(self, *_a) -> None:
        def work():
            try:
                self.broker.ensure_unlocked()
            except (Denied, VaultError):
                pass
            self._refresh()
        threading.Thread(target=work, daemon=True).start()

    def _on_lock(self, *_a) -> None:
        self.vault.lock(reason="tray menu")
        self.broker.cache.clear()
        self._refresh()

    def _on_forget(self, *_a) -> None:
        n = self.broker.cache.clear()
        audit.record("grants_cleared", count=n)
        self._refresh()

    @staticmethod
    def _open(path) -> None:
        try:
            os.startfile(str(path))  # noqa: S606 - user asked to open their own file
        except (OSError, AttributeError):
            subprocess.Popen(["notepad.exe", str(path)])

    def _on_open_log(self, *_a) -> None:
        p = audit_path()
        if not p.exists():
            p.write_text("", encoding="utf-8")
        self._open(p)

    def _on_open_config(self, *_a) -> None:
        self._open(config_path())

    def _on_quit(self, *_a) -> None:
        self._stopping.set()
        self.vault.lock(reason="quit")
        self.watchdog.stop()
        if self.api:
            self.api.stop()
        if self.icon:
            self.icon.stop()

    # ---------------------------------------------------------------- notify

    def _notify(self, title: str, message: str) -> None:
        if not config.get("notify_on_auto_approve") or not self.icon:
            return
        try:
            self.icon.notify(message, title)
        except Exception:
            pass

    def _refresh(self) -> None:
        if not self.icon:
            return
        state = "unlocked" if self.vault.is_unlocked else "locked"
        try:
            self.icon.icon = icon_mod.make(state)
            self.icon.title = f"{APP_NAME} - {self._status_text()}"
            self.icon.update_menu()
        except Exception:
            pass

    def _refresh_loop(self) -> None:
        while not self._stopping.wait(20):
            self._refresh()

    # ------------------------------------------------------------------- run

    def run(self) -> int:
        if not self.vault.bw_path:
            _fatal("Bitwarden CLI (bw) was not found on PATH.\n\n"
                   "Install it, for example:\n  winget install Bitwarden.CLI\n\n"
                   "then start bwprx again.")
            return 2

        self.ui.start()

        port = int(config.get("port"))
        try:
            self.api = ApiServer(self.broker, port)
        except OSError as exc:
            _fatal(f"Could not listen on 127.0.0.1:{port}.\n\n"
                   f"{exc}\n\nbwprx may already be running - check the tray.")
            return 3

        self.broker.on_activity = self._notify
        self.api.start()
        self.watchdog.start()

        self._refresh_thread = threading.Thread(target=self._refresh_loop,
                                                name="bwprx-refresh", daemon=True)
        self._refresh_thread.start()

        self.icon = pystray.Icon(
            APP_NAME, icon_mod.make("locked"),
            f"{APP_NAME} - starting", self._build_menu())
        self._refresh()
        audit.record("app_started", port=self.api.port, pid=os.getpid())
        self.icon.run()
        audit.record("app_stopped")
        return 0


def _fatal(message: str) -> None:
    try:
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(f"{APP_NAME} cannot start", message)
        root.destroy()
    except Exception:
        print(message, file=sys.stderr)


def main() -> int:
    try:
        return TrayApp().run()
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
