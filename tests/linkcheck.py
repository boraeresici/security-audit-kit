"""Print every relative markdown link (and #anchor) that does not resolve. Stdlib only.

Usage: python3 tests/linkcheck.py FILE.md...   (from the repo root; e2e runs it on README + docs/)
Anchors follow GitHub's slugs: lowercase, punctuation dropped, spaces to hyphens. Code blocks are
skipped, and http(s)/mailto links are not fetched.
"""
import pathlib
import re
import sys


def slug(heading):
    h = re.sub(r"[`*]", "", heading).strip().lower()
    return re.sub(r"[^\w\- ]", "", h, flags=re.U).replace(" ", "-")


def anchors(path):
    return {slug(m.group(1)) for m in re.finditer(r"^#{1,6} (.*)$", path.read_text(), re.M)}


for f in sys.argv[1:]:
    p = pathlib.Path(f)
    text = re.sub(r"```.*?```", "", p.read_text(), flags=re.S)
    for m in re.finditer(r"\[[^\]]+\]\(([^)\s]+)\)", text):
        target = m.group(1)
        if re.match(r"^[a-z]+:", target):
            continue
        path, _, frag = target.partition("#")
        tp = (p.parent / path) if path else p
        if not tp.exists():
            print(f"{f}: missing {target}")
        elif frag and tp.suffix == ".md" and frag not in anchors(tp):
            print(f"{f}: no anchor {target}")
