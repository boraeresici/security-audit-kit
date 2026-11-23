#!/usr/bin/env python3
"""`scan.sh ui` — a local view of the scan record (R13a), which can start a scan (R13b) and record
a person's decision about a finding (R13c).

A small HTTP server, standard library only, bound to 127.0.0.1 on an ephemeral port. It shows what
`scan.sh` last recorded for ONE repository, fixed at start: the gate verdict, each dimension's
status, the findings with their fingerprints, evidence and a person's decision (read live from
docs/security/decisions.json). It writes nothing itself and serves no file by path: a start runs
`scan.sh fast|all`, a decision runs `scan.sh decide`, each with a fixed argv and integrity-checked.

Threat model (docs/threat-model.md has the row): any web page the user visits can send requests to
127.0.0.1, and the record itself can be planted by whoever wrote the checked-out branch. So:
- Host must be exactly 127.0.0.1:<port> (DNS rebinding); `localhost` is refused too.
- A one-time token printed in the terminal is exchanged for a session cookie whose name carries
  the port (localhost cookies are shared across ports). Both are compared in constant time, and
  request logging is off so the token never reaches a log.
- GET and HEAD, plus POST to four fixed routes (form token, exact Origin). Reads are of two fixed
  files under docs/security/scan-findings/, decisions.json and the scan lock's owner file, each a
  regular file reached through no symlink, under a size cap.
- The record is shaped before rendering (report_html.clean_doc); any exception is a fixed 500.
- Every page says where the record came from: its commit against HEAD, a warning when a record
  file is tracked by git (a branch can commit a forged one), a banner while a scan holds the lock,
  and a warning when evidence.json is not the current summary.json's run.
"""
from __future__ import annotations

import argparse
import datetime
import hmac
import http.server
import json
import os
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # run with python3 -I -B (no __pycache__ in the kit)
sys.dont_write_bytecode = True

import decisions as dec  # noqa: E402
import report_html as rh  # noqa: E402

RECORD = "docs/security/scan-findings"
CAPS = {"summary.json": 1 << 20, "evidence.json": 64 << 20, "owner": 4096}
FP_CHARS = 20
IDLE_SEC = 2 * 3600
MAX_CONCURRENT = 8
SOCKET_TIMEOUT = 10
GIT_TIMEOUT = 5
RUNS = ("fast", "all")                     # R13b: the only commands the UI starts
OUTPUT_CAP = 64 * 1024
POST_CAP = 1024
DECISIONS_REL = "docs/security/decisions.json"   # R13c: read to show, written only by scan.sh decide
DECISIONS_CAP = 4 << 20
DECIDE_CAP = 64 << 10                       # two 2000-character fields of non-ASCII text, percent-encoded
DECIDE_TIMEOUT = 30
DECIDE_FIELDS = {"ft", "fp", "decision", "evidence_kind", "reason", "until", "verify", "owner"}
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
FP_RE = re.compile(r"^[0-9a-f]{20}$")
# route -> (fields allowed, fields that may be missing, body cap, max fields)
POSTS = {
    "/run": ({"ft", "cmd"}, set(), POST_CAP, 4),
    "/run/cancel": ({"ft"}, set(), POST_CAP, 4),
    "/decide": (DECIDE_FIELDS, {"decision"}, DECIDE_CAP, 8),     # an unchecked radio sends nothing
    "/decide/remove": ({"ft", "fp"}, set(), POST_CAP, 4),
}
REVIEW_KEYS = ("decision", "evidence_kind", "reason", "owner", "decided", "until", "verify")
CANCEL_TERM_SEC, CANCEL_KILL_SEC = 10, 20
# The scan's environment is built, not inherited: these pass through; SKIP_SECURITY and every other
# kit knob do not. GATE_STRICT passes, so a user who set it does not get a laxer UI run.
ENV_KEEP = {"PATH", "HOME", "USER", "LOGNAME", "LANG", "TMPDIR", "SHELL", "DOCKER_HOST", "DOCKER_CONTEXT",
            "DOCKER_CONFIG", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
            "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "GATE_STRICT"}
ENV_PREFIXES = ("LC_", "XDG_")
ANSI = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]")


class Unreadable(Exception):
    """A record file that must not or cannot be read. The message is safe to show."""


def read_fixed(root: str, rel: str, cap: int):
    """Bytes of root/rel, or None when it does not exist. Refuses a symlink anywhere on the way, a
    non-regular file, a path that resolves outside root, and anything over cap."""
    root = os.path.realpath(root)
    path = root
    for part in rel.split("/"):
        path = os.path.join(path, part)
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise Unreadable(f"{rel}: cannot be read ({exc.__class__.__name__})") from None
        if stat.S_ISLNK(st.st_mode):
            raise Unreadable(f"{rel}: a symbolic link is on its path; not followed")
    if not stat.S_ISREG(st.st_mode):
        raise Unreadable(f"{rel}: not a regular file")
    if os.path.realpath(path) != os.path.join(root, *rel.split("/")):
        raise Unreadable(f"{rel}: resolves outside the repository")
    if st.st_size > cap:
        raise Unreadable(f"{rel}: {st.st_size} bytes, over the {cap}-byte limit")
    with open(path, "rb") as fh:
        data = fh.read(cap + 1)
    if len(data) > cap:
        raise Unreadable(f"{rel}: over the {cap}-byte limit")
    return data


def read_json(root: str, name: str):
    data = read_fixed(root, f"{RECORD}/{name}", CAPS[name])
    if data is None:
        return None
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise Unreadable(f"{name}: not valid JSON") from None


def git(root: str, *args) -> str:
    """git output, or "" on any failure. GIT_OPTIONAL_LOCKS=0: no index refresh, so no write."""
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
    try:
        r = subprocess.run(["git", "-C", root, *args], capture_output=True, text=True,
                           timeout=GIT_TIMEOUT, env=env, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    return r.stdout.strip() if r.returncode == 0 else ""


def lock_owner(root: str):
    """The scan lock's owner fields while a scan holds it, else None. Read, never taken."""
    common = git(root, "rev-parse", "--git-common-dir")
    if not common:
        return None
    if not os.path.isabs(common):
        common = os.path.join(root, common)
    owner = os.path.join(common, "security-audit-cache", "scan.lock", "owner")
    try:
        st = os.lstat(owner)
        if not stat.S_ISREG(st.st_mode) or st.st_size > CAPS["owner"]:
            return None
        with open(owner, encoding="utf-8", errors="replace") as fh:
            text = fh.read(CAPS["owner"])
    except OSError:
        return None
    fields = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    pid = fields.get("pid", "")
    # A lock left by a crashed or killed scan is not a running scan: scan.sh reclaims it on its next
    # run. Only a pid on this host can be checked; another host's lock is shown as held.
    if fields.get("host") == socket.gethostname() and pid.isdigit():
        try:
            os.kill(int(pid), 0)
        except ProcessLookupError:
            return None
        except (PermissionError, OverflowError):
            pass
    return {k: fields.get(k, "") for k in ("cmd", "date", "pid")}


def provenance(root: str, summary, doc) -> tuple:
    """(plain-text origin line, list of (css class, warning text)) for every page."""
    notes = []
    prov = ((doc or {}).get("scan") or {}).get("provenance") or {}
    if not isinstance(prov, dict):
        prov = {}
    head = git(root, "rev-parse", "HEAD")
    commit = prov.get("commit") if isinstance(prov.get("commit"), str) else ""
    if commit and head:
        if commit == head:
            line = f"record of commit {commit[:12]} = HEAD" + (" (working tree was dirty)" if prov.get("dirty") else "")
        else:
            line = f"record of commit {commit[:12]}; HEAD is now {head[:12]}"
            notes.append(("warn", "This record is of an older commit than the one checked out. Re-run the scan to see the current code."))
    else:
        line = "record of an unknown commit"
    tracked = git(root, "ls-files", "--", f"{RECORD}/summary.json", f"{RECORD}/evidence.json")
    if tracked:
        notes.append(("bad", "A record file is tracked by git (" + ", ".join(tracked.split()) + "). The kit never "
                      "commits it, so this copy came with the branch and can be anything. Do not read it as a "
                      "scan result; run the scan yourself."))
    owner = lock_owner(root)
    if owner:
        notes.append(("warn", f"A scan is running ({owner['cmd'] or 'unknown command'}, started {owner['date'] or '?'}, "
                      f"pid {owner['pid'] or '?'}). This page shows the last completed record; reload when it ends."))
    job = JOB_REF[0]
    if job is not None and job.state == "running":
        notes.append(("warn", f"A scan started here is running ({job.cmd}). Its progress is on the run page."))
    if summary and doc and rh.scan_time(summary, (doc.get("scan") or {})) is None:
        notes.append(("warn", "evidence.json is not from the run in summary.json (a scan without SARIF=1, or a "
                      "publish in progress). The verdict below is evidence.json's own."))
    return line, notes


JOB_REF = [None]          # the server's current job, for the banner (one server per process)


def banner_html(notes) -> str:
    return "".join(f'<div class="panel notice {cls}">{rh.esc(text)}</div>' for cls, text in notes)


NAV = '<p class="sub"><a href="/">record</a> · <a href="/run">run</a> · local view · <code>scan.sh ui</code></p>'
EXTRA_CSS = (".notice{border-left:4px solid var(--medium);margin:.6rem 0}"
             # the run form: an action card, styled like the report's filter bar, with one clear button
             ".action{display:flex;flex-wrap:wrap;gap:.6rem .9rem;align-items:end;margin:.8rem 0 1.2rem;"
             "border-left:4px solid var(--low)}"
             ".action h2{margin:0 1rem 0 0;font-size:1rem;align-self:center}"
             ".action label{display:flex;flex-direction:column;gap:.2rem;font-size:.76rem;color:var(--muted);"
             "text-transform:uppercase;letter-spacing:.06em}"
             ".action select{font:inherit;font-size:.92rem;padding:.42rem .6rem;border:1px solid var(--line);"
             "border-radius:6px;background:var(--panel);color:var(--ink);min-width:7rem}"
             ".btn{font:inherit;font-size:.92rem;font-weight:600;padding:.45rem 1.1rem;border-radius:6px;"
             "border:1px solid var(--ink);background:var(--ink);color:var(--bg);cursor:pointer}"
             ".btn:hover{opacity:.88}.btn:focus-visible,.action select:focus-visible{outline:2px solid var(--low);outline-offset:2px}"
             ".btn.danger{background:transparent;color:var(--bad);border-color:var(--bad)}"
             ".action .hint{flex-basis:100%;font-size:.82rem;color:var(--muted)}"
             # run output: kept inside its panel; wide tool tables scroll sideways instead of spilling
             "pre.out{margin:0;max-height:70vh;overflow:auto;white-space:pre;font-size:.8rem;line-height:1.35}"
             ".notice.bad{border-left-color:var(--bad);color:var(--bad)}"
             "dl.kv{display:grid;grid-template-columns:max-content 1fr;gap:.25rem 1rem}"
             "a{color:var(--low);text-decoration:none}a:hover{text-decoration:underline}"
             "dl.kv dt{color:var(--muted)}dl.kv dd{margin:0;overflow-wrap:anywhere}"
             # the decision form (R13c)
             ".decide{display:flex;flex-direction:column;gap:.7rem;border-left:4px solid var(--low);margin:.8rem 0}"
             ".decide h2{margin:0;font-size:1rem}"
             ".decide fieldset{border:1px solid var(--line);border-radius:6px;padding:.5rem .8rem;margin:0;"
             "display:flex;flex-direction:column;gap:.3rem}"
             ".decide legend,.decide label{font-size:.76rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}"
             ".decide label{display:flex;flex-direction:column;gap:.2rem}"
             ".decide label.opt{flex-direction:row;align-items:baseline;gap:.45rem;text-transform:none;letter-spacing:0;"
             "font-size:.9rem;color:var(--ink)}.decide label.opt span{color:var(--muted);font-size:.84rem}"
             ".decide .row{display:flex;flex-wrap:wrap;gap:.7rem}"
             ".decide textarea,.decide input[type=text],.decide input[type=date],.decide select{font:inherit;font-size:.92rem;"
             "padding:.42rem .6rem;border:1px solid var(--line);border-radius:6px;background:var(--panel);color:var(--ink);"
             "text-transform:none;letter-spacing:0}"
             ".decide textarea{width:100%;box-sizing:border-box;resize:vertical}"
             ".decide .btn{align-self:flex-start}.decide .hint{font-size:.82rem;color:var(--muted)}")
HEADER_CSP = rh.CSP + "; frame-ancestors 'none'"
FORM_CSP = rh.CSP.replace("form-action 'none'", "form-action 'self'")       # pages that carry a form
FORM_HEADER_CSP = FORM_CSP + "; frame-ancestors 'none'"


def page(title: str, body: str, csp: str = rh.CSP, head: str = "") -> str:
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<meta http-equiv="Content-Security-Policy" content="{csp}">{head}'
            f'<title>{rh.esc(title)}</title><style>{rh.CSS}{EXTRA_CSS}</style></head>'
            f'<body><div class="wrap">{body}</div></body></html>')


def kv(rows) -> str:
    return '<dl class="kv">' + "".join(
        f"<dt>{rh.esc(k)}</dt><dd>{rh.esc(v)}</dd>" for k, v in rows if v not in (None, "", [], {})) + "</dl>"


def live_decisions(root: str):
    """(record or None, problem or None): docs/security/decisions.json as it is now, validated. A
    missing file is an empty record. Read like the record files: no symlink on the way, capped."""
    data = read_fixed(root, DECISIONS_REL, DECISIONS_CAP)
    if data is None:
        return None, None
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None, "not valid JSON"
    problems = dec.validate(doc)
    if problems:
        return None, "; ".join(problems[:3]) + (f" (+{len(problems) - 3} more)" if len(problems) > 3 else "")
    return doc, None


def decisions_git_notes(root: str) -> list:
    """The record is a committed file: say when what is on disk is not what is committed."""
    if not os.path.lexists(os.path.join(root, *DECISIONS_REL.split("/"))):
        return []
    if git(root, "check-ignore", "--", DECISIONS_REL):
        return [("warn", f"{DECISIONS_REL} is ignored by git: decisions written here will not reach the repository.")]
    if git(root, "status", "--porcelain", "--", DECISIONS_REL):
        return [("warn", f"{DECISIONS_REL} is modified, or new and not yet added: commit it with the change it explains.")]
    return []


def overlay(doc: dict, root: str) -> tuple:
    """Lay the current decisions.json over the record's findings, in memory (R13c).

    evidence.json's `review` is what the record said when the scan built it; a decision written
    from this page would otherwise show only after the next scan. Every scan-time review is removed
    first, so a removed decision disappears, then decisions.apply_reviews (the evidence builder's
    own code) sets them again from the live file. Nothing is written.
    -> (notes, record or None, problem or None); problem means the decision form must not be offered."""
    notes = []
    before = {f.get("fingerprint"): tuple((f.get("review") or {}).get(k) for k in REVIEW_KEYS)
              for f in doc["findings"] if f.get("review")}
    doc["warnings"] = [w for w in doc["warnings"]
                       if not w.startswith(dec.WARN_NOT_USED) and dec.WARN_UNSEEN not in w]
    for f in doc["findings"]:
        f.pop("review", None)
    try:
        record, problem = live_decisions(root)
    except Unreadable as exc:
        record, problem = None, str(exc)
    if problem:
        notes.append(("bad", f"decisions.json not used: {problem}. No decision is shown, and none can be written "
                      "here until the file is fixed or restored from git."))
        return notes, None, problem
    warnings = []
    try:
        dec.apply_reviews(doc["findings"], record, warnings)
    except Exception as exc:              # noqa: BLE001 — a branch-authored file must not take the page down
        for f in doc["findings"]:
            f.pop("review", None)
        problem = f"could not be applied ({exc.__class__.__name__})"
        notes.append(("bad", f"decisions.json not used: {problem}."))
        return notes, None, problem
    for f in doc["findings"]:
        r = f.get("review")
        if r:
            f["review"] = {k: (v if v is None or isinstance(v, (str, list)) else str(v)) for k, v in r.items()}
    after = {f.get("fingerprint"): tuple(f["review"].get(k) for k in REVIEW_KEYS)
             for f in doc["findings"] if f.get("review")}
    if before != after:
        notes.append(("warn", "Decisions are shown live from decisions.json; evidence.json is updated by the next scan."))
    notes += [("warn", w) for w in warnings]
    return notes, record, None


class Record:
    """One read of the record, shaped, with the live decisions laid over it. Errors are kept as
    text, never raised to the handler."""

    def __init__(self, root: str):
        self.error = None
        self.summary = self.doc = self.decisions = None
        self.notes, self.decide_problem = [], None
        try:
            s = read_json(root, "summary.json")
            self.summary = s if isinstance(s, dict) else None
            raw = read_json(root, "evidence.json")
            self.doc = rh.clean_doc(raw) if raw is not None else None
        except (Unreadable, rh.BadRecord) as exc:
            self.error = str(exc)
        if self.doc is not None:
            self.notes, self.decisions, self.decide_problem = overlay(self.doc, root)
            self.notes += decisions_git_notes(root)


def run_form(form_token: str) -> str:
    opts = "".join(f'<option value="{c}">{c}</option>' for c in RUNS)
    return ('<form method="post" action="/run" class="panel action">'
            '<h2>Run a scan</h2>'
            f'<input type="hidden" name="ft" value="{rh.esc(form_token)}">'
            f'<label>command<select name="cmd">{opts}</select></label>'
            '<button type="submit" class="btn">Start scan</button>'
            '<span class="hint">fast: staged secrets + dependencies, seconds · all: every dimension in '
            "'all'. The same command as in a terminal, with SARIF=1 REPORT=html so this record updates; "
            'the kit is integrity-checked first.</span></form>')


def render_index(root: str, today: str, form_token: str = "") -> str:
    rec = Record(root)
    form = run_form(form_token) if form_token else ""
    if rec.error or rec.doc is None:
        why = rec.error or "no evidence.json yet: run a scan with SARIF=1 (for example SARIF=1 bash tools/security-audit-kit/scan.sh all)."
        origin, notes = provenance(root, rec.summary, None)
        return page("Security scan — no record", f"<h1>Security scan</h1>{NAV}"
                    f'<p class="sub">{rh.esc(root)} · {rh.esc(origin)}</p>{banner_html(notes)}{form}'
                    f'<div class="panel notice bad">{rh.esc(why)}</div>', csp=FORM_CSP)
    origin, notes = provenance(root, rec.summary, rec.doc)
    return rh.render_report(rec.doc, rec.summary, os.path.basename(root), today, origin=origin,
                            banner=banner_html(notes + rec.notes) + form, nav=NAV, link_fingerprints=True,
                            csp=FORM_CSP if form else rh.CSP, extra_css=EXTRA_CSS)


def decision_form(fp: str, form_token: str, review: dict, values, owner_default: str, today: datetime.date) -> str:
    """The R13c form. `values` (a refused submit) wins over the current decision, which wins over
    the defaults. The HTML constraints are hints; decisions.py decides."""
    cur = values if values is not None else {k: review.get(k) or "" for k in REVIEW_KEYS} if review else {}
    owner = values.get("owner", "") if values is not None else owner_default    # who replaces it answers for it
    kind = cur.get("evidence_kind") or "unverified"
    ft = f'<input type="hidden" name="ft" value="{rh.esc(form_token)}"><input type="hidden" name="fp" value="{rh.esc(fp)}">'
    radios = "".join(
        f'<label class="opt"><input type="radio" name="decision" value="{rh.esc(d)}"'
        f'{" checked" if cur.get("decision") == d else ""}> <b>{rh.esc(d)}</b> <span>{rh.esc(why)}</span></label>'
        for d, why in dec.DECISIONS.items())
    kinds = "".join(f'<option value="{k}"{" selected" if kind == k else ""}>{k}</option>' for k in dec.EVIDENCE_KINDS)
    lo, hi = (today + datetime.timedelta(days=1)).isoformat(), (today + datetime.timedelta(days=dec.MAX_ACCEPT_DAYS)).isoformat()
    replace = bool(review)
    form = ('<form method="post" action="/decide" class="panel decide">'
            f'<h2>{"Replace the decision" if replace else "Record a decision"}</h2>{ft}'
            f'<fieldset><legend>decision</legend>{radios}</fieldset>'
            f'<label>reason (required)<textarea name="reason" rows="3" maxlength="{dec.MAX_TEXT}" required>'
            f'{rh.esc(cur.get("reason") or "")}</textarea></label>'
            '<div class="row">'
            f'<label>evidence kind<select name="evidence_kind">{kinds}</select></label>'
            f'<label>until (required for accepted)<input type="date" name="until" min="{lo}" max="{hi}" '
            f'value="{rh.esc(cur.get("until") or "")}"></label>'
            f'<label>owner<input type="text" name="owner" maxlength="{dec.MAX_OWNER}" value="{rh.esc(owner or "")}"></label>'
            '</div>'
            f'<label>verify (required for needs-validation: what would settle it)<textarea name="verify" rows="2" '
            f'maxlength="{dec.MAX_TEXT}">{rh.esc(cur.get("verify") or "")}</textarea></label>'
            f'<button type="submit" class="btn">{"Replace decision" if replace else "Record decision"}</button>'
            '<span class="hint">Runs scan.sh decide, which writes docs/security/decisions.json; commit it with the change '
            'it explains. A decision is on record only: it never changes what blocks a push. To stop a finding from '
            'blocking, use the scanner\'s allowlist (scan.sh allowlist audits them).</span></form>')
    if replace:
        form += ('<form method="post" action="/decide/remove" class="panel action">'
                 f'{ft}<button type="submit" class="btn danger">Remove decision</button>'
                 '<span class="hint">Deletes the entry from decisions.json. If it was never committed, git cannot '
                 'bring it back; the notice after removing repeats it.</span></form>')
    return form


def render_finding(root: str, fp: str, form_token: str = "", owner_default: str = "", values=None,
                   message=None) -> tuple:
    """(status, page). With a form token (the kit is known) the page carries the decision form.
    `message` is (css class, text) shown above it: a refusal, a result, a notice."""
    rec = Record(root)
    if rec.error or rec.doc is None:
        return 404, page("Not found", f"<h1>Finding</h1>{NAV}<div class='panel'>{rh.esc(rec.error or 'no record')}</div>")
    rows = [f for f in rec.doc["findings"] if f.get("fingerprint") == fp]
    if not rows:
        return 404, page("Not found", f"<h1>Finding</h1>{NAV}<div class='panel'>No finding with this fingerprint in the current record.</div>")
    origin, notes = provenance(root, rec.summary, rec.doc)
    parts = [f"<h1>Finding {rh.esc(fp[:12])}</h1>{NAV}<p class='sub'>{rh.esc(origin)}</p>{banner_html(notes + rec.notes)}"]
    for f in rows:
        pkg = f.get("package") or {}
        ev = f.get("evidence") or {}
        parts.append('<div class="panel">' + kv([
            ("tool", f.get("tool")), ("rule", f.get("rule_id")), ("dimension", f.get("dimension")),
            ("severity", f"{f.get('severity')} ({f.get('severity_source') or '?'})"),
            ("location", rh.location(f)), ("message", f.get("message")),
            ("package", " ".join(str(pkg.get(k) or "") for k in ("ecosystem", "name", "version")).strip()),
            ("aliases", ", ".join(str(a) for a in f.get("aliases") or [] if isinstance(a, str))),
            ("fixed in", ", ".join(str(a) for a in f.get("fixed_in") or [] if isinstance(a, str))),
            ("triage", rh.DECISION_LABEL.get(f.get("decision"), f.get("decision"))),
            ("confidence", f.get("confidence")),
            ("evidence: source", ev.get("source")), ("evidence: note", ev.get("note")),
            ("fingerprint", f"{f.get('fingerprint')} ({f.get('fingerprint_basis') or '?'})"), ("id", f.get("id")),
        ]) + "</div>")
    review = rows[0].get("review") or {}
    if review.get("decision"):
        today = time.strftime("%Y-%m-%d")
        flags = (["EXPIRED — review again"] if rh.expired(review, today) else []) + \
                [f"changed since: {c}" for c in review.get("changed") or []]
        parts.append("<h2>A person's decision</h2><div class='panel'>" + kv([
            ("decision", rh.REVIEW_LABEL.get(review.get("decision"), review.get("decision"))),
            ("owner", review.get("owner")), ("decided", review.get("decided")), ("until", review.get("until")),
            ("evidence kind", review.get("evidence_kind")), ("reason", review.get("reason")),
            ("verify", review.get("verify")), ("flags", " · ".join(flags)),
        ]) + "<p class='sub'>On record only: a decision never changes what blocks a push.</p></div>")
    if message:
        parts.append(f'<div class="panel notice {message[0]}"><pre class="out">{rh.esc(message[1])}</pre></div>')
    form = bool(form_token)
    if form and rec.decide_problem:
        parts.append(f"<div class='panel notice bad'>No decision can be written here: decisions.json {rh.esc(rec.decide_problem)}.</div>")
        form = False
    elif form:
        parts.append(decision_form(fp, form_token, review, values, owner_default, datetime.date.today()))
    return 200, page(f"Finding {fp[:12]}", "".join(parts), csp=FORM_CSP if form else rh.CSP)


def integrity(root: str, kit: str) -> tuple:
    """(ok, message): the kit against the manifest recorded at install, with the git dir's own copy
    of integrity.sh, exactly as the git hook wrappers do. The server outlives a `git checkout`, so a
    click must not run a scan.sh that a branch changed."""
    common = git(root, "rev-parse", "--git-common-dir")
    if not common:
        return False, "not a git repository"
    if not os.path.isabs(common):
        common = os.path.join(root, common)
    state, checker = os.path.join(common, "security-audit-install.state"), os.path.join(common, "security-audit-hooks", "integrity.sh")
    anchor = ""
    try:
        with open(state, encoding="utf-8", errors="replace") as fh:
            for line in fh.read(65536).splitlines():
                if line.startswith("kit_anchor="):
                    anchor = line.split("=", 1)[1].strip()
    except OSError:
        pass
    if not anchor or not os.path.isfile(checker):
        return False, "no install record for the kit in this repository (run install.sh), so nothing is started"
    try:
        r = subprocess.run(["bash", checker, kit, anchor], capture_output=True, text=True, timeout=60,
                           stdin=subprocess.DEVNULL, cwd=root)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"the integrity check could not run ({exc.__class__.__name__})"
    if r.returncode != 0:
        return False, "the vendored kit is not the one installed here, so it was not run:\n" + (r.stdout + r.stderr)[:4000]
    return True, ""


def scan_env() -> dict:
    env = {k: v for k, v in os.environ.items() if k in ENV_KEEP or k.startswith(ENV_PREFIXES)}
    env.update({"TERM": "dumb", "SARIF": "1", "REPORT": "html", "SCAN_LOCK_BUSY": "exit", "SCAN_LOCK_WAIT": "5"})
    return env


class Job:
    """One scan the UI started. State comes from the process's exit, never from its output."""

    def __init__(self, root: str, kit: str, cmd: str, bash: str):
        self.root, self.cmd = root, cmd
        self.started = time.time()
        self.buf = bytearray()
        self.lock = threading.Lock()
        self.state, self.rc, self.ended = "running", None, None
        self.cancel_requested = False
        self.proc = subprocess.Popen([bash, os.path.join(kit, "scan.sh"), cmd], cwd=root, env=scan_env(),
                                     stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     start_new_session=True, close_fds=True)
        threading.Thread(target=self._read, daemon=True).start()
        threading.Thread(target=self._wait, daemon=True).start()

    def _read(self):
        fd = self.proc.stdout.fileno()
        while True:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                return
            if not chunk:
                return
            with self.lock:
                self.buf += chunk
                if len(self.buf) > OUTPUT_CAP:
                    del self.buf[:len(self.buf) - OUTPUT_CAP]

    def _wait(self):
        rc = self.proc.wait()
        with self.lock:
            self.rc, self.ended = rc, time.time()
            self.state = self._end_state(rc)

    def published(self) -> bool:
        """Did this run publish the record? scan.sh's RUN_ID ends in -$$, which is this pid."""
        try:
            s = read_json(self.root, "summary.json")
        except Unreadable:
            return False
        return isinstance(s, dict) and str(s.get("run_id", "")).endswith(f"-{self.proc.pid}")

    def _end_state(self, rc: int) -> str:
        if rc in (130, 143):
            return "cancelled"
        if rc < 0:
            return "killed"
        if rc == 1 and not self.published() and b"SCAN_LOCK_BUSY=exit" in bytes(self.buf):
            return "not started"
        return {0: "passed", 1: "blocked", 3: "indeterminate"}.get(rc, "error")

    def output(self) -> str:
        with self.lock:
            data = ANSI.sub(b"", bytes(self.buf))
        return data.decode("utf-8", "replace")

    def cancel(self):
        """SIGINT to the group (scan.sh publishes nothing and releases the lock), then TERM, then KILL."""
        with self.lock:
            if self.state != "running":
                return
            self.cancel_requested = True
        for sig, delay in ((signal.SIGINT, 0), (signal.SIGTERM, CANCEL_TERM_SEC), (signal.SIGKILL, CANCEL_KILL_SEC)):
            threading.Timer(delay, self._signal, (sig,)).start()

    def _signal(self, sig):
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, sig)
            except (ProcessLookupError, PermissionError):
                pass


END_NOTES = {
    "passed": "passed: the gate let it through",
    "blocked": "blocked: the gate stopped it (findings or a failed scanner; see the output and the record)",
    "indeterminate": "indeterminate: nothing could be inspected; not a pass",
    "cancelled": "cancelled: nothing was published; the record on the record page is the previous one",
    "killed": "killed: the scan did not stop in time and was killed; its lock may be left (scan.sh reclaims it on the next run), "
              "and a scanner container may still run (docker ps)",
    "not started": "not started: another scan holds the lock; nothing was run. Retry when it is done",
    "error": "error: scan.sh ended with an unexpected exit code; see the output",
}


def render_run(ui) -> str:
    job = ui.job
    if job is None:
        return page("Run", f"<h1>Run</h1>{NAV}<div class='panel'>No scan was started from this page yet. "
                    f"Start one on the <a href='/'>record</a> page.</div>")
    with job.lock:
        state, rc, ended, cancel_req = job.state, job.rc, job.ended, job.cancel_requested
    elapsed = int((ended or time.time()) - job.started)
    rows = [("command", f"scan.sh {job.cmd}"), ("state", state), ("started", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(job.started))),
            ("elapsed", f"{elapsed}s"), ("exit code", rc)]
    extra, head, csp = "", "", rh.CSP
    if state == "running":
        head = '<meta http-equiv="refresh" content="2">'
        csp = FORM_CSP
        extra = ('<form method="post" action="/run/cancel" class="panel action">'
                 f'<input type="hidden" name="ft" value="{rh.esc(ui.form_token)}">'
                 '<button type="submit" class="btn danger">Cancel scan</button>'
                 '<span class="hint">SIGINT to the scan, then TERM and KILL if it does not stop; a cancelled scan publishes nothing.</span></form>')
    else:
        published = job.published()
        note = END_NOTES.get(state, state)
        if cancel_req and published:
            note = "cancel was requested, but the run had already finished and published its record"
        rows.append(("record", "this run's: see the record page" if published else "not updated by this run"))
        s = {}
        if published:
            try:
                s = read_json(job.root, "summary.json") or {}
            except Unreadable:
                s = {}
        blockers = [d for d in s.get("dimensions") or [] if isinstance(d, dict) and d.get("gate") == "block"]
        if state == "blocked" and blockers:
            named = ", ".join(f"{d.get('name')} (scan error, not a finding)" if d.get("status") == "error"
                              else f"{d.get('name')} ({d.get('status')})" for d in blockers)
            errors = any(d.get("status") == "error" for d in blockers)
            note = (f"blocked by {named}: a commit or push would be stopped. "
                    + ("A scanner failed: fix the scan, do not allowlist it." if errors else
                       "This is the gate doing its job, not a failure of the page or the scan: triage the findings "
                       "(/sec-triage), fix them, or allowlist a false positive with an expiry."))
        cls = "" if state == "passed" else "bad" if state in ("error", "killed") or (state == "blocked" and any(
            d.get("status") == "error" for d in blockers)) else "warn"
        extra = f'<div class="panel notice {cls}">{rh.esc(note)}</div>'
        if published:
            gaps = [f"{d.get('name')} ({d.get('status')})" for d in s.get("dimensions") or []
                    if isinstance(d, dict) and d.get("status") in rh.NOT_INSPECTED]
            if gaps:
                extra += f'<div class="panel notice">Not inspected: {rh.esc(", ".join(gaps))} — not a pass for those.</div>'
    body = (f"<h1>Run</h1>{NAV}<div class='panel'>{kv(rows)}</div>{extra}"
            f"<h2>Output (last {OUTPUT_CAP // 1024} KiB)</h2><div class='panel'><pre class='out'>{rh.esc(job.output())}</pre></div>")
    return page(f"Run — {state}", body, csp=csp, head=head)


class UI:
    """State shared by the handler threads: the root, the port, the token, the sessions."""

    def __init__(self, root: str, port: int = 0, idle_sec: int = IDLE_SEC, kit: str = ""):
        self.root = os.path.realpath(root)
        self.kit = os.path.realpath(kit) if kit else ""
        self.bash = shutil.which("bash") or "/bin/bash"      # resolved once, at start
        self.form_token = ""
        self.job = None
        self.token = secrets.token_urlsafe(32)
        self.token_spent = False
        self.session = None
        self.lock = threading.Lock()
        self.start_lock = threading.Lock()
        self.decide_lock = threading.Lock()   # R13c: one write of decisions.json at a time
        self.flash = None                     # (fingerprint, css class, text): shown once, on that finding's GET
        self.slots = threading.BoundedSemaphore(MAX_CONCURRENT)
        self.last = time.monotonic()
        self.idle_sec = idle_sec
        self.server = Server(("127.0.0.1", port), Handler)
        self.server.ui = self
        self.port = self.server.server_address[1]
        self.host = f"127.0.0.1:{self.port}"
        self.cookie = f"sak_ui_{self.port}"

    def url(self) -> str:
        return f"http://{self.host}/?t={self.token}"

    def exchange(self, token: str):
        """The session value for a correct, unspent token, else None."""
        with self.lock:
            if self.token_spent or not hmac.compare_digest(token.encode(), self.token.encode()):
                return None
            self.token_spent = True
            self.session = secrets.token_urlsafe(32)
            self.form_token = secrets.token_urlsafe(32)
            return self.session

    def has_session(self, value: str) -> bool:
        with self.lock:
            return bool(self.session) and hmac.compare_digest(value.encode(), self.session.encode())

    def start(self, cmd: str) -> tuple:
        """(http status, message). One job at a time; integrity first."""
        if not self.kit:
            return 409, "the kit's location is unknown, so nothing can be started (run it as scan.sh ui)"
        with self.start_lock:                 # one start at a time; the session lock stays free
            if self.job is not None and self.job.state == "running":
                return 409, "a scan started here is still running"
            ok, why = integrity(self.root, self.kit)
            if not ok:
                return 409, why
            self.job = Job(self.root, self.kit, cmd, self.bash)
            JOB_REF[0] = self.job
            return 303, ""

    def decide_ready(self) -> tuple:
        """(ok, why): the checks before scan.sh decide runs, made here and not only by the page
        hiding its form. decisions.py follows symlinks, so its target is checked first."""
        if not self.kit:
            return False, "the kit's location is unknown, so nothing can be written (run it as scan.sh ui)"
        try:
            _, problem = live_decisions(self.root)
        except Unreadable as exc:
            return False, f"decisions.json: {exc}"
        if problem:
            return False, f"decisions.json is not valid ({problem}); fix it or restore it from git"
        return integrity(self.root, self.kit)

    def run_decide(self, args: list) -> tuple:
        """(exit code or None on timeout, output). Its own process group, killed whole on timeout."""
        env = dict(scan_env(), PYTHONUTF8="1")
        proc = subprocess.Popen([self.bash, os.path.join(self.kit, "scan.sh"), "decide", *args], cwd=self.root,
                                env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, close_fds=True)
        try:
            out, err = proc.communicate(timeout=DECIDE_TIMEOUT)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            out, err = proc.communicate()
            rc = None
        text = ANSI.sub(b"", out + (b"\n" if out and err else b"") + err).decode("utf-8", "replace").strip()
        return rc, text[-4096:]

    def watch_idle(self):
        while True:
            time.sleep(min(60, max(1, self.idle_sec / 4)))
            if self.job is not None and self.job.state == "running":
                continue                      # never stop under a running scan
            if time.monotonic() - self.last > self.idle_sec:
                self.server.shutdown()        # from this thread, never the serving one
                return


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "security-audit-kit-ui"
    sys_version = ""
    timeout = SOCKET_TIMEOUT
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):     # the request line carries the token: never logged
        return

    def respond(self, code: int, body: str = "", headers=None, form: bool = False):
        data = body.encode("utf-8")
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Security-Policy", FORM_HEADER_CSP if form else HEADER_CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        # A page with a form must not be no-referrer: browsers then send `Origin: null` on its own
        # POST, which the exact-Origin check refuses. same-origin keeps the Referer off other sites.
        self.send_header("Referrer-Policy", "same-origin" if form else "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def send_error(self, code, message=None, explain=None):   # no request text reflected
        text = {400: "Bad request", 403: "Forbidden", 404: "Not found", 405: "Method not allowed",
                408: "Request timeout", 414: "URI too long", 500: "Server error", 503: "Busy"}.get(code, "Error")
        try:
            self.respond(code, page(text, f"<h1>{code} {text}</h1>"), {"Connection": "close"})
        except OSError:
            pass

    def deny(self, code: int, why: str):
        self.respond(code, page("Forbidden", f"<h1>{code}</h1><div class='panel'>{rh.esc(why)}</div>"))

    def do_GET(self):
        ui = self.server.ui
        if not ui.slots.acquire(blocking=False):
            return self.send_error(503)
        try:
            ui.last = time.monotonic()
            self.route(ui)
        except Exception:                 # noqa: BLE001 — a fixed page, never a traceback
            try:
                self.send_error(500)
            except Exception:             # noqa: BLE001
                pass
        finally:
            ui.slots.release()

    do_HEAD = do_GET

    def do_POST(self):
        ui = self.server.ui
        if not ui.slots.acquire(blocking=False):
            return self.send_error(503)
        try:
            ui.last = time.monotonic()
            self.post(ui)
        except Exception:                 # noqa: BLE001
            try:
                self.send_error(500)
            except Exception:             # noqa: BLE001
                pass
        finally:
            ui.slots.release()

    def do_PUT(self):
        self.send_error(405)

    do_DELETE = do_PATCH = do_OPTIONS = do_PUT

    def session_ok(self, ui) -> bool:
        cookies = {}
        for part in self.headers.get("Cookie", "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookies[k] = v
        return ui.has_session(cookies.get(ui.cookie, ""))

    def post(self, ui):
        """The only state-changing requests: start and cancel a scan (R13b), write and remove a
        decision (R13c). Every R13a check, then the cross-site ones: exact Origin (missing or null
        refused), Sec-Fetch-Site same-origin when sent, a urlencoded body under the route's cap with
        exactly the expected fields, and the session's form token in constant time."""
        if self.headers.get("Host", "") != ui.host:
            return self.deny(403, f"This server answers only at {ui.host}.")
        path = urllib.parse.urlsplit(self.path).path
        if path not in POSTS:
            return self.send_error(405)
        allowed, optional, cap, max_fields = POSTS[path]
        if not self.session_ok(ui):
            return self.deny(403, "No session. Open the link scan.sh ui printed in your terminal.")
        if self.headers.get("Origin", "") != f"http://{ui.host}":
            return self.deny(403, "Cross-site request refused (Origin).")
        if self.headers.get("Sec-Fetch-Site") not in (None, "same-origin"):
            return self.deny(403, "Cross-site request refused (Sec-Fetch-Site).")
        if not self.headers.get("Content-Type", "").split(";")[0].strip() == "application/x-www-form-urlencoded":
            return self.deny(415, "Unsupported content type.")
        length = self.headers.get("Content-Length", "")
        if not length.isdigit() or int(length) > cap:
            return self.deny(413, f"A form body under {cap // 1024} KiB is required.")
        try:
            raw = self.rfile.read(int(length)).decode("ascii")
            # keep_blank_values: a browser sends empty fields (until=&verify=), which are not missing
            form = urllib.parse.parse_qs(raw, keep_blank_values=True, strict_parsing=bool(raw),
                                         max_num_fields=max_fields, encoding="utf-8", errors="strict")
        except ValueError:                # UnicodeDecodeError included
            return self.deny(400, "Malformed form.")
        if not set(form) <= allowed or not (allowed - optional) <= set(form) or any(len(v) != 1 for v in form.values()):
            return self.deny(400, "Unexpected form fields.")
        if not ui.form_token or not hmac.compare_digest(form["ft"][0].encode(), ui.form_token.encode()):
            return self.deny(403, "The form is stale or not from this page. Reload and try again.")
        values = {k: v[0] for k, v in form.items()}
        if path == "/run/cancel":
            if ui.job is not None:
                ui.job.cancel()
            return self.respond(303, "", {"Location": "/run"})
        if path == "/run":
            cmd = values["cmd"]
            if cmd not in RUNS:
                return self.deny(400, "Not a command this page starts.")
            code, why = ui.start(cmd)
            if code != 303:
                return self.respond(code, page("Not started", f"<h1>Not started</h1>{NAV}<div class='panel notice bad'>"
                                               f"<pre>{rh.esc(why)}</pre></div>"))
            return self.respond(303, "", {"Location": "/run"})
        return self.decide(ui, path, values)

    def decide(self, ui, path: str, values: dict):
        """R13c: scan.sh decide with a fixed argv. Values travel as --opt=value, so one that starts
        with "-" is never read as an option; the fingerprint and decision are checked before they
        become positionals. Nothing is committed."""
        fp = values["fp"]
        if not FP_RE.match(fp):
            return self.deny(400, "A fingerprint is 20 lowercase hex characters.")
        if any("\x00" in v for v in values.values()):
            return self.deny(400, "Malformed form.")
        owner = git(ui.root, "config", "user.name")

        def again(code, why, cls="bad", keep=True):
            c, body = render_finding(ui.root, fp, ui.form_token, owner, values if keep else None, (cls, why))
            return self.respond(code if c == 200 else c, body, form=True)

        if path == "/decide":
            if values.get("evidence_kind") not in dec.EVIDENCE_KINDS:
                return self.deny(400, "Not an evidence kind.")
            if values.get("decision") not in dec.DECISIONS:
                return again(422, "Choose a decision.")
            if values["until"] and not DATE_RE.match(values["until"]):
                return again(422, "until: expected YYYY-MM-DD.")
            rec = Record(ui.root)
            if rec.doc is None or not any(f.get("fingerprint") == fp for f in rec.doc["findings"]):
                return self.deny(409, "This finding is not in the current record, so no decision is written about it.")
            args = [fp, values["decision"], f"--reason={values['reason']}", f"--evidence-kind={values['evidence_kind']}"]
            args += [f"--{k}={values[k]}" for k in ("owner", "until", "verify") if values[k]]
            removed = None
        else:
            try:
                record, _ = live_decisions(ui.root)
            except Unreadable:
                record = None
            removed = next((d for d in (record or {}).get("decisions") or [] if d.get("fingerprint") == fp), None)
            if removed is None:
                return self.deny(409, "There is no decision about this finding in decisions.json.")
            args = ["remove", fp]
        with ui.decide_lock:
            ok, why = ui.decide_ready()
            if not ok:
                return again(409, "Nothing was written: " + why)
            rc, text = ui.run_decide(args)
        if rc == 0:
            if removed is not None:
                text += ("\nRemoved: " + " · ".join(str(removed.get(k)) for k in ("decision", "reason", "owner", "decided", "until")
                                                   if removed.get(k)) + "\nIf it was never committed, this is the only copy.")
            ui.flash = (fp, "", text)
            return self.respond(303, "", {"Location": f"/finding/{fp}"})
        if rc == 2:
            return again(422, text or "scan.sh decide refused it.")
        return again(500, ("scan.sh decide did not finish in time." if rc is None else f"scan.sh decide exited {rc}.")
                     + " The decision may have been written; what this page shows is read live from decisions.json.\n"
                     + text, keep=True)

    def route(self, ui: UI):
        if self.headers.get("Host", "") != ui.host:
            return self.deny(403, f"This server answers only at {ui.host}.")
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/" and "t" in query:
            session = ui.exchange(query["t"][0])
            if not session:
                return self.deny(403, "This link was already used or is wrong. Restart scan.sh ui for a new one.")
            return self.respond(303, "", {"Location": "/",
                                          "Set-Cookie": f"{ui.cookie}={session}; HttpOnly; SameSite=Strict; Path=/"})
        if not self.session_ok(ui):
            return self.deny(403, "No session. Open the link scan.sh ui printed in your terminal.")
        if parsed.path == "/":
            return self.respond(200, render_index(ui.root, time.strftime("%Y-%m-%d"), ui.form_token if ui.kit else ""),
                                form=bool(ui.kit))
        if parsed.path == "/run":
            return self.respond(200, render_run(ui), form=True)
        if parsed.path.startswith("/finding/"):
            fp = parsed.path[len("/finding/"):]
            if len(fp) != FP_CHARS or any(c not in "0123456789abcdef" for c in fp):
                return self.send_error(404)
            message = None
            flash = ui.flash
            if flash and flash[0] == fp and self.command == "GET":
                ui.flash, message = None, flash[1:]
            ft = ui.form_token if ui.kit else ""
            code, body = render_finding(ui.root, fp, ft, git(ui.root, "config", "user.name") if ft else "", None, message)
            return self.respond(code, body, form=bool(ft))
        return self.send_error(404)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="scan.sh ui", description="Read-only local view of the scan record.")
    ap.add_argument("--root", required=True)
    ap.add_argument("--kit", default="", help="the vendored kit (scan.sh passes it); without it nothing can be started")
    ap.add_argument("--open", action="store_true", help="open the browser (puts the link in a process's arguments)")
    ap.add_argument("--idle-sec", type=int, default=IDLE_SEC, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    if not os.path.isdir(a.root):
        print(f"[scan:ui] not a directory: {a.root}", file=sys.stderr)
        return 2
    try:
        ui = UI(a.root, idle_sec=a.idle_sec, kit=a.kit)
    except OSError as exc:
        print(f"[scan:ui] cannot listen on 127.0.0.1 ({exc.__class__.__name__})", file=sys.stderr)
        return 2
    socket.setdefaulttimeout(SOCKET_TIMEOUT)
    print(f"[scan:ui] {ui.root}")
    print(f"[scan:ui] open: {ui.url()}")
    print("[scan:ui] read-only; the link works once and sets a session cookie. Ctrl-C to stop "
          f"(stops by itself after {a.idle_sec // 60} min without a request).", flush=True)
    if a.open:
        import webbrowser
        webbrowser.open(ui.url())
    threading.Thread(target=ui.watch_idle, daemon=True).start()

    def stop(*_):                         # SIGTERM / SIGHUP: like Ctrl-C, never an orphaned scan
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGHUP, stop)
    try:
        ui.server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        ui.server.server_close()
        job = ui.job
        if job is not None and job.state == "running":
            print("[scan:ui] cancelling the scan started here ...", flush=True)
            job.cancel()
            try:
                job.proc.wait(timeout=CANCEL_KILL_SEC + 5)
            except subprocess.TimeoutExpired:
                pass
    print("[scan:ui] stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
