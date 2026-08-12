#!/usr/bin/env python3
"""Render evidence.json as ONE self-contained HTML file you can attach, mail, or print to PDF.

Deliberately not a report platform and not a local web server: no JS framework, no external
fetches, no fonts, no build step, no new dependency — open the file from a USB stick on a machine
with no network and it looks the same. That constraint is the feature; a security artifact you
cannot open in five years is not evidence.

It renders MORE than `kit.sarif`: every finding, including the scanner ones carrying a triage
decision, which SARIF deliberately leaves to each tool's own run.

Stdlib only. Deterministic: the only date shown is the scan's own, so re-rendering unchanged input
produces an identical file.

Usage:  report_html.py --evidence <evidence.json> --out <report.html> [--repo <name>]
"""
from __future__ import annotations

import argparse
import html
import json
import sys

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}
DECISION_LABEL = {
    "real": "REAL", "fp": "false positive", "uncertain": "uncertain",
    "suppressed": "suppressed", None: "not triaged",
}

CSS = """
:root{
  --bg:#fbfbfa; --panel:#fff; --ink:#1b1b1a; --muted:#6b6b68; --line:#e3e3df;
  --critical:#8b1a1a; --high:#b03a1a; --medium:#8a6a12; --low:#3f6b8a; --info:#6b6b68;
  --ok:#2f6b3f; --bad:#8b1a1a;
}
@media (prefers-color-scheme:dark){
  :root{ --bg:#141413; --panel:#1c1c1a; --ink:#eceae4; --muted:#a1a09a; --line:#32312e;
    --critical:#e07a6f; --high:#e0a06f; --medium:#d8c47a; --low:#8fb6d1; --info:#a1a09a;
    --ok:#7fb98d; --bad:#e07a6f; }
}
*{box-sizing:border-box}
body{margin:0;padding:2.2rem 1.4rem 4rem;background:var(--bg);color:var(--ink);
  font:15px/1.55 ui-sans-serif,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1080px;margin:0 auto}
h1{font-size:1.5rem;margin:0 0 .25rem;letter-spacing:-.01em}
h2{font-size:1.05rem;margin:2.4rem 0 .8rem;letter-spacing:-.005em}
.sub{color:var(--muted);margin:0 0 1.6rem;font-size:.92rem}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:1rem 1.1rem}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:.9rem 1.4rem}
.meta div span{display:block;color:var(--muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.06em}
.meta div b{font-weight:600;font-variant-numeric:tabular-nums}
.chips{display:flex;flex-wrap:wrap;gap:.4rem;margin-top:.9rem}
.chip{font-size:.8rem;padding:.16rem .55rem;border-radius:999px;border:1px solid var(--line);
  background:transparent;font-variant-numeric:tabular-nums}
.chip.pass{color:var(--ok);border-color:currentColor}
.chip.fail{color:var(--bad);border-color:currentColor}
.bars{display:grid;gap:.42rem;margin-top:.2rem}
.bar{display:grid;grid-template-columns:5.2rem 1fr 2.4rem;align-items:center;gap:.7rem;font-size:.86rem}
.bar i{height:.62rem;border-radius:3px;display:block;min-width:2px}
.bar b{text-align:right;font-variant-numeric:tabular-nums;font-weight:600}
table{width:100%;border-collapse:collapse;margin-top:.2rem;font-size:.88rem}
th,td{text-align:left;padding:.5rem .6rem;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:.76rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);font-weight:600}
tbody tr:last-child td{border-bottom:0}
td.loc{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.82rem;word-break:break-all}
td.num{font-variant-numeric:tabular-nums;white-space:nowrap}
.sev{font-weight:700;white-space:nowrap}
.sev.critical{color:var(--critical)} .sev.high{color:var(--high)} .sev.medium{color:var(--medium)}
.sev.low{color:var(--low)} .sev.info{color:var(--info)}
.dec{font-size:.8rem;white-space:nowrap}
.ev{color:var(--muted);font-size:.82rem;margin-top:.25rem}
.scroll{overflow-x:auto}
.empty{color:var(--muted);font-style:italic;padding:.6rem 0}
footer{margin-top:2.6rem;padding-top:1rem;border-top:1px solid var(--line);color:var(--muted);font-size:.82rem}
@media print{
  body{padding:0;background:#fff;color:#000;font-size:11pt}
  .panel{border:1px solid #bbb;break-inside:avoid}
  tr,.bar{break-inside:avoid}
  h2{break-after:avoid}
  a{text-decoration:none;color:inherit}
}
"""


def esc(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def location(finding: dict) -> str:
    path = finding.get("file") or "—"
    return f"{path}:{finding['line']}" if finding.get("line") else path


def severity_bars(counts: dict, total: int) -> str:
    rows = []
    for sev in SEVERITY_ORDER:
        n = counts.get(sev, 0)
        width = (n / total * 100) if total else 0
        rows.append(
            f'<div class="bar"><span class="sev {sev}">{sev}</span>'
            f'<i style="width:{width:.1f}%;background:var(--{sev});opacity:{1 if n else .18}"></i>'
            f"<b>{n}</b></div>"
        )
    return f'<div class="bars">{"".join(rows)}</div>'


def finding_rows(findings: list) -> str:
    if not findings:
        return '<tr><td colspan="5" class="empty">Nothing in this section.</td></tr>'
    rows = []
    for f in findings:
        ev = f.get("evidence") or {}
        detail = []
        if ev.get("source"):
            detail.append(f"source: {esc(ev['source'])}")
        # For a suppressed row the reason IS the message; printing it twice reads like a bug.
        if ev.get("note") and ev["note"] != f.get("message"):
            detail.append(esc(ev["note"]))
        detail_html = f'<div class="ev">{" · ".join(detail)}</div>' if detail else ""
        cvss = f" · CVSS {f['cvss']:g}" if f.get("cvss") is not None else ""
        conf = f"{f['confidence']:g}" if f.get("confidence") is not None else "—"
        rows.append(
            "<tr>"
            f'<td class="sev {esc(f.get("severity"))}">{esc(f.get("severity"))}'
            f'<div class="ev">{esc(f.get("severity_source"))}{cvss}</div></td>'
            f'<td>{esc(f.get("tool"))}<div class="ev">{esc(f.get("rule_id"))}</div></td>'
            f'<td class="loc">{esc(location(f))}</td>'
            f'<td>{esc(f.get("message"))}{detail_html}</td>'
            f'<td class="dec">{esc(DECISION_LABEL.get(f.get("decision"), f.get("decision")))}'
            f'<div class="ev num">conf {conf}</div></td>'
            "</tr>"
        )
    return "".join(rows)


def table(findings: list) -> str:
    return (
        '<div class="panel scroll"><table><thead><tr>'
        "<th>Severity</th><th>Tool / rule</th><th>Location</th><th>Finding</th><th>Decision</th>"
        f"</tr></thead><tbody>{finding_rows(findings)}</tbody></table></div>"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Render evidence.json as a single-file HTML report")
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--repo", default="")
    ap.add_argument("--date", default="", help="scan date; falls back to summary metadata")
    args = ap.parse_args()

    try:
        with open(args.evidence, encoding="utf-8") as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        print(f"[scan:report] no evidence.json at {args.evidence} -> no report written")
        return 0
    except ValueError as exc:
        print(f"[scan:report] evidence.json is not valid JSON ({exc})", file=sys.stderr)
        return 1

    if not str(doc.get("schema", "")).startswith("security-audit-kit/evidence@1"):
        print(f"[scan:report] unsupported evidence schema {doc.get('schema')!r}", file=sys.stderr)
        return 1

    scan = doc.get("scan") or {}
    counts = doc.get("counts") or {}
    by_sev = counts.get("by_severity") or {}
    by_dec = counts.get("by_decision") or {}
    total = counts.get("total", 0)

    findings = list(doc.get("findings") or [])
    findings.sort(key=lambda f: (
        SEVERITY_RANK.get(f.get("severity"), 99), f.get("file") or "", f.get("line") or 0, f["id"]
    ))
    reported = [f for f in findings if f.get("decision") != "suppressed"]
    suppressed = [f for f in findings if f.get("decision") == "suppressed"]

    dimensions = scan.get("dimensions") or []
    chips = "".join(
        f'<span class="chip {esc(d.get("status"))}">{esc(d.get("name"))} · {esc(d.get("status"))}</span>'
        for d in dimensions
    ) or '<span class="chip">no dimensions recorded</span>'

    gate = "findings present (exit 1)" if scan.get("exit_code") else "clean (exit 0)"
    repo = args.repo or "this repository"
    date = args.date or "—"
    warnings = doc.get("warnings") or []
    warn_html = ""
    if warnings:
        items = "".join(f"<li>{esc(w)}</li>" for w in warnings)
        warn_html = f'<h2>Notes from the builder</h2><div class="panel"><ul>{items}</ul></div>'

    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security scan report — {esc(repo)} — {esc(date)}</title>
<style>{CSS}</style></head><body><div class="wrap">
<h1>Security scan report</h1>
<p class="sub">{esc(repo)} · {esc(date)} · generated locally by security-audit-kit — nothing left this machine.</p>

<div class="panel">
  <div class="meta">
    <div><span>Scope</span><b>{esc(scan.get("command") or "—")}</b></div>
    <div><span>Gate</span><b>{esc(gate)}</b></div>
    <div><span>Findings</span><b>{total}</b></div>
    <div><span>Reported / suppressed</span><b>{len(reported)} / {len(suppressed)}</b></div>
  </div>
  <div class="chips">{chips}</div>
</div>

<h2>Severity</h2>
<div class="panel">{severity_bars(by_sev, total)}</div>

<h2>Triage</h2>
<div class="panel"><div class="chips">
  <span class="chip">real {by_dec.get("real", 0)}</span>
  <span class="chip">uncertain {by_dec.get("uncertain", 0)}</span>
  <span class="chip">false positive {by_dec.get("fp", 0)}</span>
  <span class="chip">suppressed {by_dec.get("suppressed", 0)}</span>
  <span class="chip">not triaged {by_dec.get("undecided", 0)}</span>
</div></div>

<h2>Findings ({len(reported)})</h2>
{table(reported)}

<h2>Suppressed ({len(suppressed)}) — on record, not reported</h2>
{table(suppressed)}
{warn_html}

<footer>
Rendered from <code>evidence.json</code> ({esc(doc.get("schema"))}); schema and per-tool severity
mapping: <code>docs/schema/evidence.md</code>. Severity is normalized from each tool's own value,
never invented; a CVSS is shown only where a tool supplied one. This is <b>internal evidence</b> —
it does not replace an external ASV scan or a penetration test. Findings marked
<i>not triaged</i> have not been judged yet; run <code>/sec-triage</code>.
</footer>
</div></body></html>
"""
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(page)
    print(f"[scan:report] wrote {args.out} ({len(reported)} reported, {len(suppressed)} suppressed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
