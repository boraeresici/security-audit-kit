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
import secrets
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
    if summary and doc and rh.scan_time(summary, (doc.get("scan") or {})) is None:
        notes.append(("warn", "evidence.json is not from the run in summary.json (a scan without SARIF=1, or a "
                      "publish in progress). The verdict below is evidence.json's own."))
    return line, notes


def banner_html(notes) -> str:
    return "".join(f'<div class="panel notice {cls}">{rh.esc(text)}</div>' for cls, text in notes)


NAV = '<p class="sub"><a href="/">record</a> · local, read-only view · <code>scan.sh ui</code></p>'
EXTRA_CSS = (".notice{border-left:4px solid var(--medium);margin:.6rem 0}"
             ".notice.bad{border-left-color:var(--bad);color:var(--bad)}"
             "dl.kv{display:grid;grid-template-columns:max-content 1fr;gap:.25rem 1rem}"
             "dl.kv dt{color:var(--muted)}dl.kv dd{margin:0;overflow-wrap:anywhere}")
HEADER_CSP = rh.CSP + "; frame-ancestors 'none'"


def page(title: str, body: str) -> str:
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<meta http-equiv="Content-Security-Policy" content="{rh.CSP}">'
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


def render_index(root: str, today: str) -> str:
    rec = Record(root)
    if rec.error or rec.doc is None:
        why = rec.error or "no evidence.json yet: run a scan with SARIF=1 (for example SARIF=1 bash tools/security-audit-kit/scan.sh all)."
        origin, notes = provenance(root, rec.summary, None)
        return page("Security scan — no record", f"<h1>Security scan</h1>{NAV}"
                    f'<p class="sub">{rh.esc(root)} · {rh.esc(origin)}</p>{banner_html(notes)}'
                    f'<div class="panel notice bad">{rh.esc(why)}</div>')
    origin, notes = provenance(root, rec.summary, rec.doc)
    return rh.render_report(rec.doc, rec.summary, os.path.basename(root), today, origin=origin,
                            banner=banner_html(notes), nav=NAV, link_fingerprints=True)


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


class UI:
    """State shared by the handler threads: the root, the port, the token, the sessions."""

    def __init__(self, root: str, port: int = 0, idle_sec: int = IDLE_SEC):
        self.root = os.path.realpath(root)
        self.token = secrets.token_urlsafe(32)
        self.token_spent = False
        self.session = None
        self.lock = threading.Lock()
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
            return self.session

    def has_session(self, value: str) -> bool:
        with self.lock:
            return bool(self.session) and hmac.compare_digest(value.encode(), self.session.encode())

    def watch_idle(self):
        while True:
            time.sleep(min(60, max(1, self.idle_sec / 4)))
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

    def respond(self, code: int, body: str = "", headers=None):
        data = body.encode("utf-8")
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Security-Policy", HEADER_CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
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
        self.send_error(405)

    do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_POST

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
        cookies = {}
        for part in self.headers.get("Cookie", "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookies[k] = v
        if not ui.has_session(cookies.get(ui.cookie, "")):
            return self.deny(403, "No session. Open the link scan.sh ui printed in your terminal.")
        if parsed.path == "/":
            return self.respond(200, render_index(ui.root, time.strftime("%Y-%m-%d")))
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
    ap.add_argument("--open", action="store_true", help="open the browser (puts the link in a process's arguments)")
    ap.add_argument("--idle-sec", type=int, default=IDLE_SEC, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    if not os.path.isdir(a.root):
        print(f"[scan:ui] not a directory: {a.root}", file=sys.stderr)
        return 2
    try:
        ui = UI(a.root, idle_sec=a.idle_sec)
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
    try:
        ui.server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        ui.server.server_close()
    print("[scan:ui] stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
