#!/usr/bin/env python3
"""`scan.sh ui` — a read-only local view of the scan record (R13a).

A small HTTP server, standard library only, bound to 127.0.0.1 on an ephemeral port. It shows what
`scan.sh` last recorded for ONE repository, fixed at start: the gate verdict, each dimension's
status, the findings with their fingerprints, evidence and a person's decision. It writes nothing,
starts nothing, and serves no file by path.

Threat model (docs/threat-model.md has the row): any web page the user visits can send requests to
127.0.0.1, and the record itself can be planted by whoever wrote the checked-out branch. So:
- Host must be exactly 127.0.0.1:<port> (DNS rebinding); `localhost` is refused too.
- A one-time token printed in the terminal is exchanged for a session cookie whose name carries
  the port (localhost cookies are shared across ports). Both are compared in constant time, and
  request logging is off so the token never reaches a log.
- GET and HEAD only. Fixed routes. Reads are of two fixed files under docs/security/scan-findings/
  and the scan lock's owner file, each a regular file reached through no symlink, under a size cap.
- The record is shaped before rendering (report_html.clean_doc); any exception is a fixed 500.
- Every page says where the record came from: its commit against HEAD, a warning when a record
  file is tracked by git (a branch can commit a forged one), a banner while a scan holds the lock,
  and a warning when evidence.json is not the current summary.json's run.
"""
from __future__ import annotations

import argparse
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
             "dl.kv dt{color:var(--muted)}dl.kv dd{margin:0;overflow-wrap:anywhere}")
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


class Record:
    """One read of the record, shaped. Errors are kept as text, never raised to the handler."""

    def __init__(self, root: str):
        self.error = None
        self.summary = self.doc = None
        try:
            s = read_json(root, "summary.json")
            self.summary = s if isinstance(s, dict) else None
            raw = read_json(root, "evidence.json")
            self.doc = rh.clean_doc(raw) if raw is not None else None
        except (Unreadable, rh.BadRecord) as exc:
            self.error = str(exc)


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
                            banner=banner_html(notes) + form, nav=NAV, link_fingerprints=True,
                            csp=FORM_CSP if form else rh.CSP, extra_css=EXTRA_CSS)


def render_finding(root: str, fp: str) -> tuple:
    rec = Record(root)
    if rec.error or rec.doc is None:
        return 404, page("Not found", f"<h1>Finding</h1>{NAV}<div class='panel'>{rh.esc(rec.error or 'no record')}</div>")
    rows = [f for f in rec.doc["findings"] if f.get("fingerprint") == fp]
    if not rows:
        return 404, page("Not found", f"<h1>Finding</h1>{NAV}<div class='panel'>No finding with this fingerprint in the current record.</div>")
    origin, notes = provenance(root, rec.summary, rec.doc)
    parts = [f"<h1>Finding {rh.esc(fp[:12])}</h1>{NAV}<p class='sub'>{rh.esc(origin)}</p>{banner_html(notes)}"]
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
        parts.append("<h2>A person's decision</h2><div class='panel'>" + kv([
            ("decision", rh.REVIEW_LABEL.get(review.get("decision"), review.get("decision"))),
            ("owner", review.get("owner")), ("decided", review.get("decided")), ("until", review.get("until")),
            ("evidence kind", review.get("evidence_kind")), ("reason", review.get("reason")),
            ("verify", review.get("verify")), ("changed since", ", ".join(review.get("changed") or [])),
        ]) + "<p class='sub'>On record only: a decision never changes what blocks a push.</p></div>")
    return 200, page(f"Finding {fp[:12]}", "".join(parts))


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
        """The only state-changing requests (R13b): start and cancel. Every R13a check, then the
        cross-site ones: exact Origin (missing or null refused), Sec-Fetch-Site same-origin when
        sent, a urlencoded body under 1 KiB with exactly the expected fields, and the session's
        form token in constant time."""
        if self.headers.get("Host", "") != ui.host:
            return self.deny(403, f"This server answers only at {ui.host}.")
        path = urllib.parse.urlsplit(self.path).path
        if path not in ("/run", "/run/cancel"):
            return self.send_error(405)
        if not self.session_ok(ui):
            return self.deny(403, "No session. Open the link scan.sh ui printed in your terminal.")
        if self.headers.get("Origin", "") != f"http://{ui.host}":
            return self.deny(403, "Cross-site request refused (Origin).")
        if self.headers.get("Sec-Fetch-Site") not in (None, "same-origin"):
            return self.deny(403, "Cross-site request refused (Sec-Fetch-Site).")
        if not self.headers.get("Content-Type", "").split(";")[0].strip() == "application/x-www-form-urlencoded":
            return self.deny(415, "Unsupported content type.")
        length = self.headers.get("Content-Length", "")
        if not length.isdigit() or int(length) > POST_CAP:
            return self.deny(413, "A form body under 1 KiB is required.")
        raw = self.rfile.read(int(length)).decode("ascii", "replace")
        try:
            form = urllib.parse.parse_qs(raw, strict_parsing=True, max_num_fields=4)
        except ValueError:
            return self.deny(400, "Malformed form.")
        want = {"ft", "cmd"} if path == "/run" else {"ft"}
        if set(form) != want or any(len(v) != 1 for v in form.values()):
            return self.deny(400, "Unexpected form fields.")
        if not ui.form_token or not hmac.compare_digest(form["ft"][0].encode(), ui.form_token.encode()):
            return self.deny(403, "The form is stale or not from this page. Reload and try again.")
        if path == "/run/cancel":
            if ui.job is not None:
                ui.job.cancel()
            return self.respond(303, "", {"Location": "/run"})
        cmd = form["cmd"][0]
        if cmd not in RUNS:
            return self.deny(400, "Not a command this page starts.")
        code, why = ui.start(cmd)
        if code != 303:
            return self.respond(code, page("Not started", f"<h1>Not started</h1>{NAV}<div class='panel notice bad'>"
                                           f"<pre>{rh.esc(why)}</pre></div>"))
        return self.respond(303, "", {"Location": "/run"})

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
            code, body = render_finding(ui.root, fp)
            return self.respond(code, body)
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
