"""Generate CyberCheck icons (16/48/128 px) with the standard library only.

A navy shield with a green check. Antialiased via 3x supersampling.

Usage:
    python make_icons.py            # writes into this folder
    python make_icons.py <out_dir>
"""

import os
import struct
import sys
import zlib

BG = (11, 31, 58)        # navy shield
FG = (61, 220, 151)      # green check
EDGE = (39, 58, 92)      # shield rim


def _png_bytes(width, height, rgb_pixels):
    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)  # 8-bit RGBA
    rows = bytearray()
    stride = width * 4
    for y in range(height):
        rows.append(0)
        rows.extend(rgb_pixels[y * stride:(y + 1) * stride])
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(bytes(rows), 9))
            + chunk(b"IEND", b""))


def _shield_contains(nx, ny):
    """Point-in-shield test in normalised 0..1 coords (crest shape)."""
    if ny < 0.06 or ny > 0.94:
        return False
    # top is a rounded rectangle, bottom tapers to a point
    if ny < 0.55:
        half = 0.40
    else:
        t = (ny - 0.55) / 0.39
        half = 0.40 * (1.0 - t * t)
    return abs(nx - 0.5) <= half


def _dist_seg(px, py, ax, ay, bx, by):
    dx, dy = bx - ax, by - ay
    if dx == 0 and dy == 0:
        return ((px - ax) ** 2 + (py - ay) ** 2) ** 0.5
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    cx, cy = ax + t * dx, ay + t * dy
    return ((px - cx) ** 2 + (py - cy) ** 2) ** 0.5


def _sample(nx, ny):
    """Return (r,g,b,a) for a normalised coordinate."""
    if not _shield_contains(nx, ny):
        return (0, 0, 0, 0)
    # rim
    rim = (not _shield_contains(nx + 0.02, ny)) or (not _shield_contains(nx - 0.02, ny)) \
        or (not _shield_contains(nx, ny + 0.02)) or (not _shield_contains(nx, ny - 0.02))
    # check mark
    d = min(
        _dist_seg(nx, ny, 0.30, 0.52, 0.44, 0.66),
        _dist_seg(nx, ny, 0.44, 0.66, 0.72, 0.34),
    )
    if d <= 0.075:
        return (*FG, 255)
    if rim:
        return (*EDGE, 255)
    return (*BG, 255)


def _make(size):
    ss = 3
    big = size * ss
    px = bytearray(size * size * 4)
    for y in range(size):
        for x in range(size):
            r = g = b = a = 0
            for sy in range(ss):
                for sx in range(ss):
                    nx = (x + (sx + 0.5) / ss) / size
                    ny = (y + (sy + 0.5) / ss) / size
                    cr, cg, cb, ca = _sample(nx, ny)
                    r += cr * ca; g += cg * ca; b += cb * ca; a += ca
            n = ss * ss
            i = (y * size + x) * 4
            if a == 0:
                px[i:i + 4] = b"\x00\x00\x00\x00"
            else:
                px[i] = round(r / a)
                px[i + 1] = round(g / a)
                px[i + 2] = round(b / a)
                px[i + 3] = round(a / n)
    return bytes(px)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    os.makedirs(out, exist_ok=True)
    for s in (16, 48, 128):
        path = os.path.join(out, f"icon{s}.png")
        with open(path, "wb") as fh:
            fh.write(_png_bytes(s, s, _make(s)))
        print("wrote", path)


if __name__ == "__main__":
    main()
