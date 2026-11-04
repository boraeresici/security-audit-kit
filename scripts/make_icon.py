#!/usr/bin/env python3
"""Regenerate the plugin's listing icon (.claude-plugin/icon.png).

The banner's mark (scripts/make_banner.py: a shield with a check) on the forest-green accent, as a
1024 px square PNG: the plugin directory wants a PNG or JPEG of 512-2048 px and takes the icon
once, at the first submission. Drawn here with exact scanline coverage, so the pixels are the same
on every machine and the e2e can check them.

Usage:  python3 scripts/make_icon.py [out.png]      (from the repo root; no dependencies)
"""
import math
import pathlib
import struct
import sys
import zlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / ".claude-plugin" / "icon.png"

SIZE, SUB = 1024, 4                  # pixels per side, sub-rows per pixel row
BG, SHIELD, CHECK = (0x0c, 0x7c, 0x4e), (0xf7, 0xfa, 0xf7), (0x0c, 0x7c, 0x4e)
SCALE = 14.0                         # mark units (36 x 43, as in the banner) -> pixels
OX, OY = (SIZE - 36 * SCALE) / 2, (SIZE - 43 * SCALE) / 2
CHECK_W = 3.6                        # stroke width in mark units (banner: 3; a touch bolder small)


def pt(x, y):
    return OX + x * SCALE, OY + y * SCALE


def cubic(p0, p1, p2, p3, n=48):
    return [tuple((1 - t) ** 3 * a + 3 * (1 - t) ** 2 * t * b + 3 * (1 - t) * t ** 2 * c + t ** 3 * d
                  for a, b, c, d in zip(p0, p1, p2, p3)) for t in (i / n for i in range(1, n + 1))]


# M18 0 L36 7 V20 C36 31 28 39 18 43 C8 39 0 31 0 20 V7 Z
SHIELD_POLY = ([pt(18, 0), pt(36, 7), pt(36, 20)]
               + cubic(pt(36, 20), pt(36, 31), pt(28, 39), pt(18, 43))
               + cubic(pt(18, 43), pt(8, 39), pt(0, 31), pt(0, 20)) + [pt(0, 7)])
CHECK_PTS = [pt(10, 21), pt(16, 27), pt(27, 14)]     # round caps and joins


def poly_spans(poly, y):
    """Even-odd spans of a polygon on the horizontal line y."""
    xs = []
    for (x0, y0), (x1, y1) in zip(poly, poly[1:] + poly[:1]):
        if (y0 <= y < y1) or (y1 <= y < y0):
            xs.append(x0 + (y - y0) * (x1 - x0) / (y1 - y0))
    xs.sort()
    return list(zip(xs[0::2], xs[1::2]))


def stroke_spans(pts, r, y):
    """Spans of a polyline stroked with radius r, round caps and joins, on line y."""
    spans = []
    for cx, cy in pts:
        if abs(y - cy) < r:
            d = math.sqrt(r * r - (y - cy) ** 2)
            spans.append((cx - d, cx + d))
    for (x0, y0), (x1, y1) in zip(pts, pts[1:]):
        L = math.hypot(x1 - x0, y1 - y0)
        nx, ny = -(y1 - y0) / L * r, (x1 - x0) / L * r
        spans += poly_spans([(x0 + nx, y0 + ny), (x1 + nx, y1 + ny), (x1 - nx, y1 - ny), (x0 - nx, y0 - ny)], y)
    spans.sort()
    merged = []
    for a, b in spans:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return merged


def cover(row, spans, w):
    """Add the exact horizontal coverage of spans (weight w) to a row of pixels."""
    for a, b in spans:
        a, b = max(a, 0.0), min(b, float(SIZE))
        if b <= a:
            continue
        ia, ib = int(a), int(b)
        if ia == ib:
            row[ia] += (b - a) * w
            continue
        row[ia] += (ia + 1 - a) * w
        for i in range(ia + 1, ib):
            row[i] += w
        if ib < SIZE:
            row[ib] += (b - ib) * w


def mix(c0, c1, t):
    return tuple(round(a + (b - a) * t) for a, b in zip(c0, c1))


def render():
    raw = bytearray()
    r = CHECK_W * SCALE / 2
    for py in range(SIZE):
        s, c = [0.0] * SIZE, [0.0] * SIZE
        for k in range(SUB):
            y = py + (k + 0.5) / SUB
            cover(s, poly_spans(SHIELD_POLY, y), 1 / SUB)
            cover(c, stroke_spans(CHECK_PTS, r, y), 1 / SUB)
        raw.append(0)                                   # filter: none
        for x in range(SIZE):
            raw += bytes(mix(mix(BG, SHIELD, min(s[x], 1.0)), CHECK, min(c[x], 1.0)))
    return raw


def png(raw):
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", SIZE, SIZE, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + chunk(b"IEND", b""))


out = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else OUT
out.write_bytes(png(render()))
print(f"wrote {out}")
