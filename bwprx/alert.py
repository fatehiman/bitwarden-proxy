"""A loud, repeating melody that plays while bwprx waits for the user.

It starts when a dialog opens (master password, approval) and stops when the
dialog closes. The user can turn it off with "Mute alert sound" in the tray menu.
"""

from __future__ import annotations

import io
import math
import struct
import threading
import wave
from typing import Optional

try:
    import winsound
except ImportError:  # not Windows: no sound, everything else still works
    winsound = None  # type: ignore[assignment]

from . import config

RATE = 22050
AMPLITUDE = 0.95  # near full scale: as loud as the system volume allows

# (frequency in Hz, length in seconds). 0 Hz is a rest.
_MELODY = [
    (784, 0.14), (988, 0.14), (1175, 0.14), (1568, 0.30), (0, 0.06),
    (1568, 0.14), (1175, 0.14), (988, 0.14), (784, 0.30), (0, 0.10),
    (880, 0.14), (1047, 0.14), (1319, 0.14), (1760, 0.30), (0, 0.06),
    (1760, 0.14), (1319, 0.14), (1047, 0.14), (880, 0.30),
    (0, 1.20),  # pause before the loop repeats
]

_lock = threading.Lock()
_depth = 0
_wav: Optional[bytes] = None


def _build_wav() -> bytes:
    frames = bytearray()
    for freq, length in _MELODY:
        n = int(RATE * length)
        for i in range(n):
            if freq == 0:
                s = 0.0
            else:
                # Square wave is much louder to the ear than a sine wave.
                s = AMPLITUDE if math.sin(2 * math.pi * freq * i / RATE) >= 0 else -AMPLITUDE
                # Short fade in/out so notes do not click.
                edge = min(i, n - 1 - i)
                if edge < 200:
                    s *= edge / 200
            frames += struct.pack("<h", int(s * 32767))
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(RATE)
        w.writeframes(bytes(frames))
    return buf.getvalue()


def start() -> None:
    """Begin the repeating melody (unless muted). Pair every call with stop()."""
    global _depth, _wav
    if winsound is None:
        return
    with _lock:
        _depth += 1
        if _depth > 1 or config.get("mute_alert"):
            return
        try:
            if _wav is None:
                _wav = _build_wav()
            winsound.PlaySound(_wav, winsound.SND_MEMORY | winsound.SND_ASYNC
                               | winsound.SND_LOOP)
        except Exception:
            pass


def stop() -> None:
    global _depth
    if winsound is None:
        return
    with _lock:
        _depth = max(0, _depth - 1)
        if _depth == 0:
            try:
                winsound.PlaySound(None, winsound.SND_PURGE)
            except Exception:
                pass


def set_muted(muted: bool) -> None:
    """Save the choice. Muting also silences a melody that is playing now."""
    config.set_value("mute_alert", bool(muted))
    if muted and winsound is not None:
        with _lock:
            try:
                winsound.PlaySound(None, winsound.SND_PURGE)
            except Exception:
                pass
