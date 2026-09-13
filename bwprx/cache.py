"""Remembered approvals.

A grant covers one action on one item asked for by one program. An agent that
uploads twenty files needs the same credential twenty times; without this it
would raise twenty dialogs. Asking for a *different* item always prompts again.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

Key = Tuple[str, str, str]  # (action, query, client)


@dataclass
class Grant:
    action: str
    query: str
    client: str
    expires_at: float
    granted_at: float
    uses: int = 0

    @property
    def seconds_left(self) -> int:
        return max(0, int(self.expires_at - time.time()))


class ApprovalCache:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._grants: Dict[Key, Grant] = {}

    @staticmethod
    def _key(action: str, query: str, client: str) -> Key:
        return (action.strip().lower(), query.strip().lower(), client.strip().lower())

    def check(self, action: str, query: str, client: str) -> Optional[Grant]:
        """Return a live grant for this exact request, counting the use."""
        k = self._key(action, query, client)
        now = time.time()
        with self._lock:
            self._purge(now)
            g = self._grants.get(k)
            if g is None:
                return None
            g.uses += 1
            return g

    def grant(self, action: str, query: str, client: str, seconds: int) -> Optional[Grant]:
        if seconds <= 0:
            return None
        now = time.time()
        g = Grant(action=action, query=query, client=client,
                  expires_at=now + seconds, granted_at=now)
        with self._lock:
            self._grants[self._key(action, query, client)] = g
        return g

    def active(self) -> List[Grant]:
        now = time.time()
        with self._lock:
            self._purge(now)
            return sorted(self._grants.values(), key=lambda g: g.expires_at)

    def clear(self) -> int:
        with self._lock:
            n = len(self._grants)
            self._grants.clear()
            return n

    def _purge(self, now: float) -> None:
        for k in [k for k, g in self._grants.items() if g.expires_at <= now]:
            self._grants.pop(k, None)
