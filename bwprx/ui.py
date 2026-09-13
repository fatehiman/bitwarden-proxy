"""All Tk work happens on one dedicated thread.

pystray owns the main thread on Windows, and Tk objects may only be touched by
the thread that created them. So this module runs a private Tk root on its own
thread and lets other threads submit callables to it and block for the answer.
"""

from __future__ import annotations

import queue
import threading
import time
import tkinter as tk
from tkinter import ttk
from typing import Any, Callable, List, Optional, Tuple

from . import config

# Buttons stay disabled this long after a dialog appears, so a keystroke or
# click already in flight cannot land on "Approve".
ARM_DELAY_MS = 500


class UiService:
    """Submit a function to be run on the Tk thread and wait for its result."""

    def __init__(self) -> None:
        self._q: "queue.Queue[Tuple[Callable, list, threading.Event]]" = queue.Queue()
        self._ready = threading.Event()
        self._root: Optional[tk.Tk] = None
        self._thread = threading.Thread(target=self._run, name="bwprx-ui", daemon=True)

    def start(self, timeout: float = 15.0) -> None:
        self._thread.start()
        if not self._ready.wait(timeout):
            raise RuntimeError("Tk UI thread failed to start")

    def _run(self) -> None:
        root = tk.Tk()
        root.withdraw()
        try:
            root.call("tk", "scaling", 1.25)
        except tk.TclError:
            pass
        self._root = root
        self._ready.set()
        self._pump()
        root.mainloop()

    def _pump(self) -> None:
        assert self._root is not None
        while True:
            try:
                fn, holder, done = self._q.get_nowait()
            except queue.Empty:
                break
            try:
                holder.append(fn(self._root))
            except Exception as exc:  # surfaced to the caller
                holder.append(exc)
            finally:
                done.set()
        self._root.after(40, self._pump)

    def call(self, fn: Callable[[tk.Tk], Any], timeout: Optional[float] = None) -> Any:
        holder: list = []
        done = threading.Event()
        self._q.put((fn, holder, done))
        if not done.wait(timeout):
            raise TimeoutError("UI call timed out")
        result = holder[0]
        if isinstance(result, Exception):
            raise result
        return result


# --------------------------------------------------------------------- shared

def _center(win: tk.Toplevel) -> None:
    win.update_idletasks()
    w, h = win.winfo_width(), win.winfo_height()
    x = (win.winfo_screenwidth() - w) // 2
    y = (win.winfo_screenheight() - h) // 3
    win.geometry(f"+{max(0, x)}+{max(0, y)}")


def _raise(win: tk.Toplevel) -> None:
    win.attributes("-topmost", True)
    win.lift()
    win.focus_force()
    try:
        win.grab_set()
    except tk.TclError:
        pass


# ------------------------------------------------------------ master password

def ask_master_password(root: tk.Tk, account: Optional[str],
                        error: Optional[str] = None) -> Optional[str]:
    win = tk.Toplevel(root)
    win.title("bwprx - unlock vault")
    win.resizable(False, False)
    frm = ttk.Frame(win, padding=16)
    frm.grid(sticky="nsew")

    ttk.Label(frm, text="Unlock the Bitwarden vault",
              font=("Segoe UI", 11, "bold")).grid(row=0, column=0, sticky="w")
    sub = f"Account: {account}" if account else "Bitwarden CLI vault"
    ttk.Label(frm, text=sub, foreground="#555").grid(row=1, column=0, sticky="w", pady=(2, 10))
    if error:
        ttk.Label(frm, text=error, foreground="#b00020",
                  wraplength=360).grid(row=2, column=0, sticky="w", pady=(0, 8))

    ttk.Label(frm, text="Master password:").grid(row=3, column=0, sticky="w")
    var = tk.StringVar()
    entry = ttk.Entry(frm, show="•", textvariable=var, width=42)
    entry.grid(row=4, column=0, sticky="ew", pady=(2, 4))

    mins = int(config.get("idle_timeout_minutes"))
    ttk.Label(frm, text=f"The session stays unlocked while in use, and locks after "
                        f"{mins} minutes idle.",
              foreground="#555", wraplength=360).grid(row=5, column=0, sticky="w", pady=(0, 12))

    result: List[Optional[str]] = [None]

    def ok(*_a):
        result[0] = var.get()
        win.destroy()

    def cancel(*_a):
        result[0] = None
        win.destroy()

    btns = ttk.Frame(frm)
    btns.grid(row=6, column=0, sticky="e")
    ttk.Button(btns, text="Cancel", command=cancel).grid(row=0, column=0, padx=(0, 8))
    ok_btn = ttk.Button(btns, text="Unlock", command=ok)
    ok_btn.grid(row=0, column=1)

    win.bind("<Return>", ok)
    win.bind("<Escape>", cancel)
    win.protocol("WM_DELETE_WINDOW", cancel)
    _center(win)
    _raise(win)
    entry.focus_force()
    root.wait_window(win)
    return result[0]


# ------------------------------------------------------------------- approval

class ApprovalRequest:
    """What the dialog needs to describe one pending request."""

    def __init__(self, action: str, title: str, summary: str,
                 details: List[Tuple[str, str]], client: str,
                 remember_choices: List[Tuple[str, int]],
                 default_remember: int = 0, danger: bool = False) -> None:
        self.action = action
        self.title = title
        self.summary = summary
        self.details = details
        self.client = client
        self.remember_choices = remember_choices
        self.default_remember = default_remember
        self.danger = danger


def ask_approval(root: tk.Tk, req: ApprovalRequest) -> Tuple[bool, int]:
    """Show the dialog. Returns (approved, remember_seconds)."""
    timeout = int(config.get("approval_timeout_seconds"))
    deadline = time.time() + timeout

    win = tk.Toplevel(root)
    win.title(req.title)
    win.resizable(False, False)
    frm = ttk.Frame(win, padding=16)
    frm.grid(sticky="nsew")

    accent = "#b00020" if req.danger else "#0b5fff"
    ttk.Label(frm, text=req.summary, font=("Segoe UI", 11, "bold"),
              foreground=accent, wraplength=430).grid(row=0, column=0, columnspan=2,
                                                      sticky="w", pady=(0, 10))

    row = 1
    for label, value in req.details:
        ttk.Label(frm, text=label, foreground="#555").grid(
            row=row, column=0, sticky="nw", padx=(0, 10))
        ttk.Label(frm, text=value, wraplength=320, justify="left").grid(
            row=row, column=1, sticky="w")
        row += 1

    ttk.Separator(frm, orient="horizontal").grid(
        row=row, column=0, columnspan=2, sticky="ew", pady=10)
    row += 1

    ttk.Label(frm, text="Asked by", foreground="#555").grid(
        row=row, column=0, sticky="nw", padx=(0, 10))
    ttk.Label(frm, text=req.client, wraplength=320, justify="left").grid(
        row=row, column=1, sticky="w")
    row += 1

    ttk.Label(frm, text="Don't ask again for", foreground="#555").grid(
        row=row, column=0, sticky="w", padx=(0, 10), pady=(10, 0))
    labels = [c[0] for c in req.remember_choices]
    remember = tk.StringVar(value=labels[0])
    for lbl, secs in req.remember_choices:
        if secs == req.default_remember:
            remember.set(lbl)
            break
    combo = ttk.Combobox(frm, values=labels, textvariable=remember,
                         state="readonly", width=18)
    combo.grid(row=row, column=1, sticky="w", pady=(10, 0))
    row += 1

    ttk.Label(frm, text="This applies to this exact item and this program only.",
              foreground="#555", wraplength=430).grid(
        row=row, column=0, columnspan=2, sticky="w", pady=(4, 12))
    row += 1

    result: List[Tuple[bool, int]] = [(False, 0)]
    countdown = tk.StringVar(value="")

    def chosen_seconds() -> int:
        for lbl, secs in req.remember_choices:
            if lbl == remember.get():
                return secs
        return 0

    def approve(*_a):
        result[0] = (True, chosen_seconds())
        win.destroy()

    def deny(*_a):
        result[0] = (False, 0)
        win.destroy()

    btns = ttk.Frame(frm)
    btns.grid(row=row, column=0, columnspan=2, sticky="ew")
    btns.columnconfigure(0, weight=1)
    ttk.Label(btns, textvariable=countdown, foreground="#777").grid(
        row=0, column=0, sticky="w")
    deny_btn = ttk.Button(btns, text="Deny", command=deny)
    deny_btn.grid(row=0, column=1, padx=(0, 8))
    ok_btn = ttk.Button(btns, text="Approve", command=approve)
    ok_btn.grid(row=0, column=2)

    # Anti-misclick: nothing is clickable for the first moments.
    ok_btn.state(["disabled"])
    deny_btn.state(["disabled"])

    def arm():
        ok_btn.state(["!disabled"])
        deny_btn.state(["!disabled"])
        ok_btn.focus_set()

    win.after(ARM_DELAY_MS, arm)

    def tick():
        left = int(deadline - time.time())
        if left <= 0:
            result[0] = (False, 0)
            try:
                win.destroy()
            except tk.TclError:
                pass
            return
        countdown.set(f"Denied automatically in {left}s")
        win.after(500, tick)

    tick()

    win.bind("<Escape>", deny)
    win.protocol("WM_DELETE_WINDOW", deny)
    _center(win)
    _raise(win)
    root.wait_window(win)
    return result[0]
