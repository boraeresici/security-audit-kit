#!/usr/bin/env python3
"""Regenerate the README banner (docs/assets/banner-{light,dark}.svg).

Same identity as the landing page: IBM Plex (the landing's own subsets, embedded as base64
because GitHub renders a README SVG as an <img>, which cannot fetch fonts), one forest-green
accent, a dark block only where it is a real terminal. The terminal shows the kit's closing
summary in its real column format, and a run that is not all green: skipped and not_applicable
are part of what the kit says, so the banner says them too.

Usage:  python3 scripts/make_banner.py        (from the repo root; no dependencies)
"""
import base64
import pathlib
from xml.sax.saxutils import escape

ROOT = pathlib.Path(__file__).resolve().parent.parent
FONTS = ROOT / "landing" / "fonts"
OUT = ROOT / "docs" / "assets"


def face(family, file, weight):
    b = base64.b64encode((FONTS / file).read_bytes()).decode()
    return (f"@font-face{{font-family:'{family}';font-weight:{weight};"
            f"src:url(data:font/woff2;base64,{b}) format('woff2')}}")


THEMES = {
    "light": dict(bg="#f7faf7", line="#e1e8e1", ink="#141f18", dim="#54655b", green="#0c7c4e",
                  wash="#eaf5ee", washline="#c9dfd1", tline="#101812"),
    "dark":  dict(bg="#0d1410", line="#1f2b24", ink="#e4eee7", dim="#93a69a", green="#3bdb8d",
                  wash="#14251b", washline="#24402f", tline="#24402f"),
}
TERM = dict(bg="#101812", txt="#c9dccf", green="#3bdb8d", dim="#6d8377", amber="#e0a646", red="#ef7d72")

DIMS = ["secrets", "SAST", "dep CVE", "IaC", "container", "SBOM", "malicious deps", "GH Actions"]
# scan.sh's closing table: "   %-10s %-14s %5.1fs  %s" (name, status, seconds, reason)
ROWS = [("secret", "pass", "1.2", "", "green"),
        ("sast", "findings", "3.4", "", "red"),
        ("py-deps", "pass", "0.9", "", "green"),
        ("js-deps", "not_applicable", "0.0", "no JS project", "dim"),
        ("container", "skipped", "0.1", "no docker", "amber"),
        ("iac", "pass", "2.1", "", "green")]


def svg(t, faces):
    w, h = 1280, 360
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
         f'role="img" aria-label="security-audit-kit: pinned scanners find, Claude judges, your git hooks gate">',
         f"<style>{faces}.s{{font-family:'Plex Sans',-apple-system,'Segoe UI',Helvetica,Arial,sans-serif}}"
         f".m{{font-family:'Plex Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}}</style>",
         f'<rect x="0.5" y="0.5" width="{w - 1}" height="{h - 1}" rx="14" fill="{t["bg"]}" stroke="{t["line"]}"/>',
         # the mark: a shield with a check
         f'<g transform="translate(56 58)"><path d="M18 0 L36 7 V20 C36 31 28 39 18 43 C8 39 0 31 0 20 V7 Z" '
         f'fill="{t["wash"]}" stroke="{t["green"]}" stroke-width="2.5" stroke-linejoin="round"/>'
         f'<path d="M10 21 L16 27 L27 14" fill="none" stroke="{t["green"]}" stroke-width="3" '
         f'stroke-linecap="round" stroke-linejoin="round"/></g>',
         f'<text x="108" y="90" class="m" font-size="30" font-weight="600" fill="{t["ink"]}">security-audit-kit</text>',
         f'<text x="56" y="152" class="s" font-size="27" font-weight="600" fill="{t["ink"]}">Pinned scanners find.</text>',
         f'<text x="56" y="188" class="s" font-size="27" font-weight="600" fill="{t["ink"]}">Claude judges. '
         f'<tspan fill="{t["green"]}">Your git hooks gate.</tspan></text>',
         f'<text x="56" y="226" class="s" font-size="16" fill="{t["dim"]}">'
         f'Local, CI-independent security scanning for any repo. No account, no upload.</text>']
    x, y = 56, 262
    for d in DIMS:
        cw = 18 + 8.4 * len(d)
        if x + cw > 640:
            x, y = 56, y + 38
        o.append(f'<rect x="{x}" y="{y}" width="{cw:.0f}" height="28" rx="14" fill="{t["wash"]}" stroke="{t["washline"]}"/>')
        o.append(f'<text x="{x + cw / 2:.0f}" y="{y + 19}" text-anchor="middle" class="m" font-size="13" '
                 f'fill="{t["ink"]}">{escape(d)}</text>')
        x += cw + 8
    tx, ty, tw, th = 690, 40, 550, 280
    o.append(f'<rect x="{tx}" y="{ty}" width="{tw}" height="{th}" rx="10" fill="{TERM["bg"]}" stroke="{t["tline"]}"/>')
    for i in range(3):
        o.append(f'<circle cx="{tx + 20 + i * 16}" cy="{ty + 18}" r="5" fill="#3a4a40"/>')
    ly = ty + 56
    o.append(f'<text x="{tx + 20}" y="{ly}" class="m" font-size="14" fill="{TERM["txt"]}">'
             f'<tspan fill="{TERM["dim"]}">$</tspan> bash scan.sh all</text>')
    ly += 30
    # "--" stands in for the real "──": the embedded Plex Mono subset has no box-drawing glyphs
    o.append(f'<text x="{tx + 20}" y="{ly}" class="m" font-size="14" fill="{TERM["green"]}">'
             f'-- run: 20261103T195012 · scan all · 7.7s</text>')
    for name, st, s, why, col in ROWS:
        ly += 22
        line = f"   {name:<10} {st:<14} {s:>5}s  {why}".rstrip()
        o.append(f'<text x="{tx + 20}" y="{ly}" class="m" font-size="14" xml:space="preserve" fill="{TERM["txt"]}">'
                 f'{escape(line[:14])}<tspan fill="{TERM[col]}">{escape(line[14:28])}</tspan>{escape(line[28:])}</text>')
    ly += 30
    o.append(f'<text x="{tx + 20}" y="{ly}" class="m" font-size="14" fill="{TERM["red"]}">-- BLOCKED (rc=1): sast (findings)</text>')
    ly += 22
    o.append(f'<text x="{tx + 20}" y="{ly}" class="m" font-size="14" fill="{TERM["green"]}">-- NEXT STEP, in Claude Code: /sec-triage</text>')
    o.append("</svg>")
    return "\n".join(o) + "\n"


def main():
    faces = "".join([face("Plex Sans", "plex-sans-var.woff2", "100 700"),
                     face("Plex Mono", "plex-mono-400.woff2", 400),
                     face("Plex Mono", "plex-mono-600.woff2", 600)])
    OUT.mkdir(parents=True, exist_ok=True)
    for name, t in THEMES.items():
        p = OUT / f"banner-{name}.svg"
        p.write_text(svg(t, faces))
        print(f"wrote {p.relative_to(ROOT)} ({p.stat().st_size // 1024} KiB)")


if __name__ == "__main__":
    main()
