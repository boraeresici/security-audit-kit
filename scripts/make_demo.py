#!/usr/bin/env python3
"""Regenerate the README demo (docs/assets/demo.svg + demo.txt) from a REAL run.

Nothing in the demo is typed by hand: a throwaway repo is built, the released kit is vendored into
it with its own bootstrap.sh, a commit with a secret is attempted, and `scan.sh all` runs. The
output (ANSI colours included) is captured and rendered as an animated terminal SVG. GitHub shows a
README SVG as an <img>, which plays CSS animations but runs no script and fetches nothing, so the
SVG is self-contained. demo.txt is the same transcript as plain text (diffable, and the alt text).

Usage:  python3 scripts/make_demo.py [TAG]     (from the repo root; default: the README's pin)
Needs:  git, docker, uvx (the run is real, so a missing tool shows up as "skipped" in the demo),
        and network access to KIT_REPO (default: this checkout's origin).
Run it at release prep, after the README pins move, so the demo shows the release users get.
"""
import html
import os
import pathlib
import re
import secrets
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "assets"
COLS, ROWS = 96, 16           # terminal size in characters
CW, LH, PAD = 9.2, 19, 18     # char width, line height, padding (px) for a 13px monospace font (with slack)
TERM = dict(bg="#101812", bar="#1a241e", txt="#c9dccf", dim="#6d8377", prompt="#3bdb8d",
            green="#3bdb8d", red="#ef7d72", amber="#e0a646", cyan="#7cc7d9")
SGR = {"31": "red", "32": "green", "33": "amber", "36": "cyan", "2": "dim", "90": "dim"}


def readme_pin():
    m = re.search(r"bash bootstrap\.sh (v\d+\.\d+\.\d+)\b", (ROOT / "README.md").read_text())
    return m.group(1) if m else sys.exit("no pinned tag found in README.md; pass one")


def sh(cmd, cwd, env=None):
    """Run a shell command; return its combined output (ANSI kept)."""
    r = subprocess.run(["bash", "-c", cmd], cwd=cwd, env=env, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, text=True)
    return r.stdout


def capture(tag):
    kit_repo = os.environ.get("KIT_REPO") or sh("git remote get-url origin", ROOT).strip()
    work = pathlib.Path(tempfile.mkdtemp(prefix="sak-demo-"))
    repo = work / "payments-api"
    try:
        repo.mkdir()
        git = "git -c user.email=demo@example.com -c user.name=demo"
        (repo / "app.py").write_text(
            "import subprocess\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n\n"
            "@app.route('/ping')\ndef ping():\n"
            "    return subprocess.check_output('ping -c1 ' + request.args['host'], shell=True)\n")
        (repo / "requirements.txt").write_text("flask==2.2.0\nrequests==2.19.0\n")
        sh(f"git init -q -b main && git add -A && {git} commit -qm 'payments api'", repo)
        boot = sh(f"git -C '{ROOT}' show {tag}:bootstrap.sh", ROOT)
        (repo / "bootstrap.sh").write_text(boot)
        env = dict(os.environ, KIT_REPO=kit_repo, TERM="xterm-256color")
        scenes = []
        out = sh(f"bash bootstrap.sh {tag}", repo, env)
        scenes.append((f"bash bootstrap.sh {tag}", out))
        sh(f"rm bootstrap.sh && git add -A && SKIP_SECURITY=1 {git} commit -qm 'vendor security-audit-kit {tag}'", repo, env)
        key = "".join(secrets.choice("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(32))
        (repo / "config.py").write_text(f'PAYMENT_API_KEY = "{key}"\n')
        out = sh(f"git add config.py && {git} commit -m 'payment config'", repo, env)
        scenes.append(("git commit -m 'payment config'", out))
        out = sh("git reset -q config.py && rm config.py && bash tools/security-audit-kit/scan.sh all", repo, env)
        scenes.append(("bash tools/security-audit-kit/scan.sh all", out))
        return scenes
    finally:
        shutil.rmtree(work, ignore_errors=True)


def clean(text):
    """Keep the lines a reader needs: drop progress noise, keep colour codes, cap the width."""
    keep = []
    for line in text.replace("\r\n", "\n").split("\n"):
        line = line.split("\r")[-1].rstrip()
        plain = re.sub(r"\x1b\[[0-9;]*m", "", line)
        if not plain.strip() or re.match(r"^\s*(Downloading|Installed|Resolved|Prepared|Building|Built|\d+:|Digest:|Status:|[0-9a-f]{12}:)", plain):
            continue
        keep.append(line)
    return keep


def scene_lines(cmd, out):
    """A scene: the prompt, then the part of the output that says what happened."""
    lines = clean(out)
    plain = [re.sub(r"\x1b\[[0-9;]*m", "", l) for l in lines]
    pick = list(range(len(lines)))
    if any("== bootstrap complete ==" in p for p in plain):           # bootstrap: its summary
        pick = pick[next(i for i, p in enumerate(plain) if "== bootstrap complete ==" in p):]
    elif any(p.startswith("── run:") for p in plain):                  # a scan: the finding + the closing summary
        run = next(i for i, p in enumerate(plain) if p.startswith("── run:"))
        found = [i for i in range(run) if re.match(r"^(Finding|RuleID|File|Line):", plain[i])]
        pick = found + list(range(run, len(lines)))
    pick = [i for i in pick if not plain[i].startswith("── raw log:")]
    rows = []
    for i in pick:
        rows += wrap(lines[i])
    return [("prompt", cmd)] + [("out", l) for l in rows[-(ROWS - 2):]]


def wrap(line):
    """Split an ANSI line at the terminal width, keeping its colour on the continuation."""
    if len(re.sub(r"\x1b\[[0-9;]*m", "", line)) <= COLS:
        return [line]
    out, cur, width, colour = [], "", 0, ""
    for part in re.split(r"(\x1b\[[0-9;]*m)", line):
        if re.fullmatch(r"\x1b\[[0-9;]*m", part):
            colour = part; cur += part; continue
        for word in re.split(r"( )", part):
            if width + len(word) > COLS and width > 0:
                out.append(cur.rstrip()); cur, width = colour + "   ", 3
                if word == " ":
                    continue
            cur += word; width += len(word)
    out.append(cur)
    return out


def spans(line):
    """ANSI line -> [(css class, text)], cut to the terminal width."""
    res, cls, width = [], "txt", 0
    for part in re.split(r"(\x1b\[[0-9;]*m)", line):
        m = re.fullmatch(r"\x1b\[([0-9;]*)m", part)
        if m:
            codes = m.group(1).split(";")
            cls = "txt" if codes in (["0"], [""]) else next((SGR[c] for c in codes if c in SGR), cls)
            continue
        if part:
            part = part[:max(0, COLS - width)]
            width += len(part)
            if part:
                res.append((cls, part))
    return res


def render(scenes):
    w = int(COLS * CW + 2 * PAD)
    h = int(ROWS * LH + 2 * PAD + 28)
    per_line, hold, type_t = 0.12, 5.0, 1.2
    plan, t = [], 0.6
    for cmd, out in scenes:
        lines = scene_lines(cmd, out)
        start = t
        times = [start]
        t += type_t
        for _ in lines[1:]:
            times.append(t)
            t += per_line
        t += hold
        plan.append((lines, times, start, t))
    total = t
    pct = lambda x: f"{100 * x / total:.3f}%"
    css = [f".t{{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace;font-size:13px;white-space:pre}}"]
    css += [f".{k}{{fill:{v}}}" for k, v in TERM.items()]
    body, n = [], 0
    for si, (lines, times, s0, s1) in enumerate(plan):
        last = si == len(plan) - 1
        end = pct(s1) if not last else "100%"
        body.append(f'<g class="sc{si}">')
        css.append(f"@keyframes sc{si}{{0%,{pct(max(s0 - 0.01, 0))}{{opacity:0}}{pct(s0)},{end}{{opacity:1}}"
                   + ("" if last else f"{pct(s1 + 0.01)},100%{{opacity:0}}") + "}")
        css.append(f".sc{si}{{animation:sc{si} {total:.2f}s linear infinite}}")
        for li, ((kind, text), at) in enumerate(zip(lines, times)):
            y = PAD + 28 + (li + 1) * LH - 4
            n += 1
            if kind == "prompt":
                css.append(f"@keyframes l{n}{{0%,{pct(at)}{{clip-path:inset(0 100% 0 0)}}{pct(at + type_t * 0.8)},100%{{clip-path:inset(0 0 0 0)}}}}")
                inner = f'<tspan class="prompt">$ </tspan><tspan class="txt">{html.escape(text)}</tspan>'
            else:
                css.append(f"@keyframes l{n}{{0%,{pct(at)}{{opacity:0}}{pct(at + 0.01)},100%{{opacity:1}}}}")
                inner = "".join(f'<tspan class="{c}">{html.escape(s)}</tspan>' for c, s in spans(text))
            css.append(f".l{n}{{animation:l{n} {total:.2f}s linear infinite}}")
            body.append(f'<text class="t l{n}" x="{PAD}" y="{y}">{inner}</text>')
        body.append("</g>")
    dots = "".join(f'<circle cx="{PAD + 6 + i * 18}" cy="{PAD - 2}" r="5" fill="{c}"/>'
                   for i, c in enumerate(("#ef7d72", "#e0a646", "#3bdb8d")))
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" '
            f'aria-label="security-audit-kit demo: install pinned, a commit with a secret is blocked, scan.sh all closing summary">'
            f"<style>{''.join(css)}</style>"
            f'<rect width="{w}" height="{h}" rx="12" fill="{TERM["bg"]}"/>'
            f'<rect width="{w}" height="{PAD + 14}" rx="12" fill="{TERM["bar"]}"/>{dots}'
            f'<text class="t dim" x="{w / 2}" y="{PAD + 2}" text-anchor="middle">~/payments-api</text>'
            + "".join(body) + "</svg>\n")


def main():
    tag = sys.argv[1] if len(sys.argv) > 1 else readme_pin()
    scenes = capture(tag)
    OUT.mkdir(parents=True, exist_ok=True)
    txt = []
    for cmd, out in scenes:
        txt.append(f"$ {cmd}")
        txt += [re.sub(r"\x1b\[[0-9;]*m", "", l) for _, l in scene_lines(cmd, out)[1:]]
        txt.append("")
    (OUT / "demo.txt").write_text(f"# security-audit-kit {tag} — generated by scripts/make_demo.py from a real run\n\n" + "\n".join(txt))
    (OUT / "demo.svg").write_text(render(scenes))
    print(f"wrote {OUT / 'demo.svg'} and demo.txt ({tag})")


if __name__ == "__main__":
    main()
