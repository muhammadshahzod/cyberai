"""Generate placeholder CyberCheck icons (16/48/128 px) with the standard library.

Usage:
    python make_icons.py            # writes into this folder
    python make_icons.py <out_dir>  # writes into <out_dir>
"""

import os
import struct
import sys
import zlib

BG = (11, 31, 58, 255)      # navy
FG = (61, 220, 151, 255)    # green


def _png_bytes(width: int, height: int, pixels: bytes) -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)  # 8-bit RGBA
    rows = bytearray()
    stride = width * 4
    for y in range(height):
        rows.append(0)  # filter: none
        rows.extend(pixels[y * stride : (y + 1) * stride])
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(bytes(rows), 9))
        + chunk(b"IEND", b"")
    )


def _dist_to_segment(px, py, ax, ay, bx, by) -> float:
    dx, dy = bx - ax, by - ay
    if dx == 0 and dy == 0:
        return ((px - ax) ** 2 + (py - ay) ** 2) ** 0.5
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    cx, cy = ax + t * dx, ay + t * dy
    return ((px - cx) ** 2 + (py - cy) ** 2) ** 0.5


def _make(size: int) -> bytes:
    px = bytearray(size * size * 4)
    thickness = max(2.0, size / 9.0)
    border = max(1.0, size / 32.0)
    inset = size * 0.13
    ax, ay = size * 0.28, size * 0.54
    bx, by = size * 0.44, size * 0.70
    cx, cy = size * 0.76, size * 0.30

    for y in range(size):
        for x in range(size):
            fx, fy = x + 0.5, y + 0.5
            edge = min(x, y, size - 1 - x, size - 1 - y)
            d = min(
                _dist_to_segment(fx, fy, ax, ay, bx, by),
                _dist_to_segment(fx, fy, bx, by, cx, cy),
            )
            if d <= thickness or (inset <= edge <= inset + border):
                color = FG
            else:
                color = BG
            i = (y * size + x) * 4
            px[i : i + 4] = bytes(color)
    return bytes(px)


def main() -> None:
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    os.makedirs(out, exist_ok=True)
    for size in (16, 48, 128):
        path = os.path.join(out, f"icon{size}.png")
        with open(path, "wb") as fh:
            fh.write(_png_bytes(size, size, _make(size)))
        print("wrote", path)


if __name__ == "__main__":
    main()
