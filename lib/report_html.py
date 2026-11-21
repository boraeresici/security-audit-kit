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
import base64
import datetime
import hashlib
import html
import json
import sys

SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown", "info"]
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
.verdict.clean b{color:var(--ok)}
.verdict.blocked b{color:var(--bad)}
.verdict.incomplete b,.verdict.unknown b,.verdict.findings b{color:var(--medium)}
.meta .verdict{grid-column:1/-1}
.chip.pass{color:var(--ok);border-color:currentColor}
.chip.fail,.chip.findings,.chip.error{color:var(--bad);border-color:currentColor}
.chip.error,.chip.skipped,.chip.indeterminate{border-style:dashed}
.chip.skipped,.chip.indeterminate{color:var(--medium);border-color:currentColor}
.chip.not_applicable{color:var(--muted)}
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
.filters{display:flex;flex-wrap:wrap;gap:.6rem .9rem;align-items:end;margin:0 0 1rem}
.filters label{display:flex;flex-direction:column;gap:.2rem;font-size:.76rem;color:var(--muted);
  text-transform:uppercase;letter-spacing:.06em}
.filters input,.filters select,.filters button{font:inherit;font-size:.88rem;padding:.32rem .5rem;
  border:1px solid var(--line);border-radius:6px;background:var(--panel);color:var(--ink)}
.filters input{min-width:14rem}
.filters button{cursor:pointer}
.filters :focus-visible{outline:2px solid var(--low);outline-offset:1px}
.fstate{flex-basis:100%;font-size:.82rem;color:var(--muted)}
details.more{margin-top:.3rem;font-size:.82rem}
details.more summary{cursor:pointer;color:var(--muted)}
details.more dl{display:grid;grid-template-columns:max-content 1fr;gap:.15rem .8rem;margin:.35rem 0 0}
details.more dt{color:var(--muted)}
details.more dd{margin:0;word-break:break-word}
footer{margin-top:2.6rem;padding-top:1rem;border-top:1px solid var(--line);color:var(--muted);font-size:.82rem}
@media print{
  body{padding:0;background:#fff;color:#000;font-size:11pt}
  .filters label,.filters button{display:none}
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


# Fields some adapters add (F16b) and the evidence the skills record, shown on demand. Plain text:
# a guideline URL is shown, not linked, so the file still loads nothing when clicked around in.
MORE_FIELDS = (
    ("package", lambda f: " ".join(str(x) for x in ((f.get("package") or {}).get(k) for k in ("ecosystem", "name", "version")) if x)),
    ("affected", lambda f: f.get("affected")),
    ("fixed in", lambda f: ", ".join(f.get("fixed_in") or [])),
    ("aliases", lambda f: ", ".join(f.get("aliases") or [])),
    ("direct", lambda f: {True: "yes", False: "no (transitive)"}.get(f.get("direct"))),
    ("resource", lambda f: f.get("resource")),
    ("detail", lambda f: f.get("detail")),
    ("guideline", lambda f: f.get("guideline")),
    ("sink", lambda f: (f.get("evidence") or {}).get("sink")),
    ("id", lambda f: f.get("id")),
)

NO_MATCH = ("No finding in this section matches the filters. That says nothing about the scan: it is "
            "not a clean result. Reset the filters to see every row.")


def more(f: dict) -> str:
    items = [(k, get(f)) for k, get in MORE_FIELDS]
    items = [(k, v) for k, v in items if v not in (None, "", [])]
    if len(items) <= 1:            # the id alone is not worth a toggle
        return ""
    dl = "".join(f"<dt>{esc(k)}</dt><dd>{esc(v)}</dd>" for k, v in items)
    return f'<details class="more"><summary>details</summary><dl>{dl}</dl></details>'


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
            f'<tr data-sev="{esc(f.get("severity"))}" data-tool="{esc(f.get("tool"))}" '
            f'data-dec="{esc(f.get("decision") or "none")}">'
            f'<td class="sev {esc(f.get("severity"))}">{esc(f.get("severity"))}'
            f'<div class="ev">{esc(f.get("severity_source"))}{cvss}</div></td>'
            f'<td>{esc(f.get("tool"))}<div class="ev">{esc(f.get("rule_id"))}</div></td>'
            f'<td class="loc">{esc(location(f))}</td>'
            f'<td>{esc(f.get("message"))}{detail_html}{more(f)}</td>'
            f'<td class="dec">{esc(DECISION_LABEL.get(f.get("decision"), f.get("decision")))}'
            f'<div class="ev num">conf {conf}</div></td>'
            "</tr>"
        )
    rows.append(f'<tr class="nomatch" hidden><td colspan="5" class="empty">{esc(NO_MATCH)}</td></tr>')
    return "".join(rows)


def table(findings: list, section: str = "reported") -> str:
    return (
        '<div class="panel scroll"><table><thead><tr>'
        "<th>Severity</th><th>Tool / rule</th><th>Location</th><th>Finding</th><th>Decision</th>"
        f'</tr></thead><tbody data-section="{section}">{finding_rows(findings)}</tbody></table></div>'
    )


# The filters are progressive enhancement: the form ships `hidden`, so a reader without JS sees the
# full tables and no control that does nothing. The script is fixed text; the page allows exactly it
# by its sha256 in the CSP, and reads the rows' data-* attributes, never an embedded data blob.
FILTER_JS = """(function () {
  var form = document.getElementById("filters");
  if (!form) { return; }
  form.hidden = false;
  var q = form.elements.q, sev = form.elements.sev, tool = form.elements.tool, dec = form.elements.dec;
  var state = document.getElementById("fstate");
  function apply() {
    var term = q.value.trim().toLowerCase(), active = [];
    if (term) { active.push("text \u201c" + q.value.trim() + "\u201d"); }
    [sev, tool, dec].forEach(function (s) { if (s.value) { active.push(s.name + " " + s.options[s.selectedIndex].text); } });
    Array.prototype.forEach.call(document.querySelectorAll("tbody[data-section]"), function (tb) {
      var rows = tb.querySelectorAll("tr[data-sev]"), shown = 0;
      Array.prototype.forEach.call(rows, function (r) {
        var ok = (!sev.value || r.getAttribute("data-sev") === sev.value) &&
                 (!tool.value || r.getAttribute("data-tool") === tool.value) &&
                 (!dec.value || r.getAttribute("data-dec") === dec.value) &&
                 (!term || r.textContent.toLowerCase().indexOf(term) !== -1);
        r.hidden = !ok;
        if (ok) { shown += 1; }
      });
      var none = tb.querySelector("tr.nomatch");
      if (none) { none.hidden = !(rows.length && shown === 0); }
      var c = document.getElementById("count-" + tb.getAttribute("data-section"));
      if (c) { c.textContent = shown === rows.length ? String(rows.length) : shown + " of " + rows.length + " shown"; }
    });
    state.textContent = active.length ? "Filtered by " + active.join(", ") + "." : "";
  }
  form.addEventListener("input", apply);
  form.addEventListener("change", apply);
  form.addEventListener("reset", function () { window.setTimeout(apply, 0); });
  form.addEventListener("submit", function (e) { e.preventDefault(); });
})();"""
SCRIPT_HASH = "sha256-" + base64.b64encode(hashlib.sha256(FILTER_JS.encode("utf-8")).digest()).decode("ascii")
CSP = f"default-src 'none'; style-src 'unsafe-inline'; script-src '{SCRIPT_HASH}'; img-src 'none'; form-action 'none'; base-uri 'none'"


def filters(findings: list) -> str:
    def opts(name, values, label=lambda v: v):
        o = "".join(f'<option value="{esc(v)}">{esc(label(v))}</option>' for v in values)
        return f'<label>{name}<select name="{name}"><option value="">all</option>{o}</select></label>'
    sevs = [s for s in SEVERITY_ORDER if any(f.get("severity") == s for f in findings)]
    tools = sorted({str(f.get("tool")) for f in findings if f.get("tool")})
    decs = [d for d in ("real", "uncertain", "fp", "suppressed", "none")
            if any((f.get("decision") or "none") == d for f in findings)]
    return (
        '<form id="filters" class="filters" role="search" aria-label="Filter the findings" hidden>'
        '<label>search<input type="search" name="q" placeholder="file, rule, package, text" autocomplete="off"></label>'
        + opts("sev", sevs) + opts("tool", tools)
        + opts("dec", decs, lambda d: DECISION_LABEL.get(None if d == "none" else d, d))
        + '<button type="reset">reset filters</button>'
        '<output id="fstate" class="fstate" aria-live="polite"></output></form>'
    )


# Statuses under which a dimension looked at nothing (summary.json schema 2).
NOT_INSPECTED = ("skipped", "error", "indeterminate")


# Dimensions recorded under another name in evidence.json (scan.sh runs the same tool over a scope).
DIMENSION_ALIASES = {"staged": "secret", "changed": "sast", "sast-changed": "sast"}


def verdict(scan: dict, reported: int, row_dims=None) -> tuple:
    """(css class, text) for the report header — F04. "clean" only when the gate passed, every
    dimension that applies inspected something, and nothing was reported. Everything short of that
    says what it is: unknown, blocked (and by what), incomplete, or passed with findings."""
    code = scan.get("exit_code")
    dims = scan.get("dimensions") or []
    if not isinstance(code, int) or isinstance(code, bool):
        return "unknown", "unknown — no gate result recorded; do not read this as a pass"
    if code == 3:
        return "incomplete", "indeterminate (exit 3) — nothing could be inspected; not a pass"
    if code != 0:
        blockers = [d for d in dims if d.get("gate") == "block"] or \
                   [d for d in dims if d.get("status") not in ("pass", None) and "gate" not in d]
        named = ", ".join(
            f'{d.get("name")} (scan error, not a finding)' if d.get("status") == "error"
            else f'{d.get("name")} ({d.get("status")})' for d in blockers)
        return "blocked", f"blocked (exit {code})" + (f": {named}" if named else "")
    if not dims:
        return "incomplete", "passed (exit 0) — no dimensions recorded, coverage unknown"
    missing = [d for d in dims if d.get("status") in NOT_INSPECTED]
    if missing:
        named = ", ".join(f'{d.get("name")} ({d.get("status")})' for d in missing)
        return "incomplete", f"passed (exit 0) — NOT complete: {named} not inspected"
    # A dimension can have findings and still write no per-finding rows (no adapter yet, F16): its
    # findings are in the scan log, so the header must not count them as 0.
    rows = set(row_dims or ())
    unlisted = [d.get("name") for d in dims if d.get("status") == "findings"
                and d.get("name") not in rows and DIMENSION_ALIASES.get(d.get("name")) not in rows]
    if unlisted:
        return "findings", (f"passed (exit 0) — findings in {', '.join(unlisted)}, not listed below (no per-finding "
                            f"rows; see the scan log)" + (f"; {reported} more listed" if reported else "") + ", none blocking")
    if reported or any(d.get("status") == "findings" for d in dims):
        return "findings", f"passed (exit 0) — {reported} finding(s) present, none blocking"
    return "clean", "clean (exit 0) — every dimension that applies was inspected"


def scan_time(summary, scan: dict):
    """(timestamp, run_id) of the run this evidence came from, or None. evidence.json carries no
    time on purpose, and summary.json may already belong to a later run (a SARIF=0 pre-commit
    publishes a new summary but leaves evidence.json alone) — so the summary's time is used only
    when its dimensions, artifacts and provenance are the evidence's own."""
    if not summary:
        return None

    def bare(dims):  # durations differ per run and never reach evidence.json
        return [{k: v for k, v in d.items() if k != "seconds"} for d in (dims or []) if isinstance(d, dict)]
    if bare(summary.get("dimensions")) != bare(scan.get("dimensions")):
        return None
    for key in ("artifacts", "provenance"):
        if summary.get(key) != scan.get(key):
            return None
    if not summary.get("timestamp"):
        return None
    return summary.get("timestamp"), summary.get("run_id")


def main() -> int:
    ap = argparse.ArgumentParser(description="Render evidence.json as a single-file HTML report")
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--repo", default="")
    ap.add_argument("--date", default="", help="report generation date (default: today)")
    ap.add_argument("--summary", default="", help="summary.json, for the scan time when it is the same run")
    args = ap.parse_args()

    try:
        with open(args.evidence, encoding="utf-8") as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        # Asked to render, nothing to render from: that is a failure the caller must be able to see.
        print(f"[scan:report] no evidence.json at {args.evidence} -> no report written", file=sys.stderr)
        return 1
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
        f'<span class="chip {esc(d.get("status"))}"'
        + (f' title="{esc(d.get("reason"))}"' if d.get("reason") else "")
        + f'>{esc(d.get("name"))} · {esc(d.get("status"))}</span>'
        for d in dimensions
    ) or '<span class="chip">no dimensions recorded</span>'

    gate_cls, gate = verdict(scan, len(reported), {f.get("dimension") for f in findings})
    repo = args.repo or "this repository"
    generated = args.date or datetime.date.today().isoformat()
    summary = None
    if args.summary:
        try:
            with open(args.summary, encoding="utf-8") as fh:
                summary = json.load(fh)
        except (OSError, ValueError):
            summary = None
    when = scan_time(summary, scan)
    if when:
        scanned = f"Scanned {when[0]}" + (f" (run {when[1]})" if when[1] else "")
        date = when[0][:10]
    else:
        scanned = "scan time unknown (no summary.json from the same run)"
        date = generated
    warnings = doc.get("warnings") or []
    warn_html = ""
    if warnings:
        items = "".join(f"<li>{esc(w)}</li>" for w in warnings)
        warn_html = f'<h2>Notes from the builder</h2><div class="panel"><ul>{items}</ul></div>'

    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{CSP}">
<title>Security scan report — {esc(repo)} — {esc(date)}</title>
<style>{CSS}</style></head><body><div class="wrap">
<h1>Security scan report</h1>
<p class="sub">{esc(repo)} · {esc(scanned)} · report generated {esc(generated)} by security-audit-kit, locally: this file was rendered offline and loads nothing. The scan's dependency lookups queried advisory services (docs/data-flow.md).</p>

<div class="panel">
  <div class="meta">
    <div><span>Scope</span><b>{esc(scan.get("command") or "—")}</b></div>
    <div class="verdict {gate_cls}"><span>Result</span><b>{esc(gate)}</b></div>
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

<h2>Findings (<span id="count-reported" aria-live="polite">{len(reported)}</span>)</h2>
{filters(findings) if findings else ""}
{table(reported, "reported")}

<h2>Suppressed (<span id="count-suppressed" aria-live="polite">{len(suppressed)}</span>) — on record, not reported</h2>
{table(suppressed, "suppressed")}
{warn_html}

<footer>
Rendered from <code>evidence.json</code> ({esc(doc.get("schema"))}); schema and per-tool severity
mapping: <code>docs/schema/evidence.md</code>. Severity is normalized from each tool's own value,
never invented; a CVSS is shown only where a tool supplied one. This is <b>internal evidence</b> —
it does not replace an external ASV scan or a penetration test. Findings marked
<i>not triaged</i> have not been judged yet; run <code>/sec-triage</code>.
</footer>
</div>
<script>{FILTER_JS}</script>
</body></html>
"""
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(page)
    print(f"[scan:report] wrote {args.out} ({len(reported)} reported, {len(suppressed)} suppressed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
