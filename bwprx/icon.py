"""Tray icon drawn at runtime, so there is no binary asset to ship."""

from __future__ import annotations

from PIL import Image, ImageDraw

LOCKED = (110, 116, 124)     # grey
UNLOCKED = (32, 150, 74)     # green
BUSY = (200, 140, 20)        # amber, while a dialog is waiting


def make(state: str = "locked", size: int = 64) -> Image.Image:
    colour = {"unlocked": UNLOCKED, "busy": BUSY}.get(state, LOCKED)
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # Shield outline
    m = size * 0.12
    top, bottom = m, size - m
    left, right = m, size - m
    mid = size / 2
    shoulder = top + (bottom - top) * 0.55
    d.polygon(
        [(left, top), (right, top), (right, shoulder),
         (mid, bottom), (left, shoulder)],
        fill=colour)

    # Keyhole
    r = size * 0.10
    cx, cy = mid, top + (bottom - top) * 0.36
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(255, 255, 255, 235))
    d.polygon(
        [(cx - r * 0.45, cy), (cx + r * 0.45, cy),
         (cx + r * 0.22, cy + r * 1.7), (cx - r * 0.22, cy + r * 1.7)],
        fill=(255, 255, 255, 235))
    return img
