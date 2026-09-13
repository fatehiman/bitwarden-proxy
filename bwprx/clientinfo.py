"""Work out which program is on the other end of a loopback connection.

The dialog should say who is asking. A field in the request body would be
trivial to lie about, so instead the caller's source port is matched against
the OS connection table to get the real PID.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

try:
    import psutil
except ImportError:  # pragma: no cover - psutil is a hard dependency in practice
    psutil = None  # type: ignore


@dataclass
class ClientInfo:
    pid: Optional[int] = None
    name: Optional[str] = None
    exe: Optional[str] = None
    cmdline: Optional[str] = None
    parent_name: Optional[str] = None

    @property
    def key(self) -> str:
        """Stable identity used in approval-cache keys."""
        return (self.exe or self.name or "unknown").lower()

    def describe(self) -> str:
        if not self.pid:
            return "unknown local process"
        who = self.name or "process"
        line = f"{who} (PID {self.pid})"
        if self.parent_name:
            line += f"\nstarted by {self.parent_name}"
        if self.cmdline:
            cmd = self.cmdline
            if len(cmd) > 160:
                cmd = cmd[:157] + "..."
            line += f"\n{cmd}"
        return line


def identify(peer_port: int) -> ClientInfo:
    if psutil is None or not peer_port:
        return ClientInfo()
    try:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.laddr and conn.laddr.port == peer_port and conn.pid:
                return _describe(conn.pid)
    except (psutil.AccessDenied, psutil.Error, OSError):
        pass
    return ClientInfo()


def _describe(pid: int) -> ClientInfo:
    info = ClientInfo(pid=pid)
    try:
        proc = psutil.Process(pid)
        info.name = proc.name()
        try:
            info.exe = proc.exe()
        except (psutil.AccessDenied, psutil.Error):
            pass
        try:
            info.cmdline = " ".join(proc.cmdline())
        except (psutil.AccessDenied, psutil.Error):
            pass
        try:
            parent = proc.parent()
            if parent:
                info.parent_name = parent.name()
        except (psutil.AccessDenied, psutil.Error):
            pass
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.Error):
        pass
    return info
