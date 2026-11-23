"""R13a: the read-only local UI. Each test is one of the design's guarantees, against a real server
on 127.0.0.1 in this process. The record files are what a branch could plant, so most tests feed
the server something hostile and check it neither breaks nor follows it."""
from __future__ import annotations

import http.client
import json
import os
import subprocess
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "lib"))

import ui_server as us  # noqa: E402

FP = "ab" * 10
EVIDENCE = {
    "schema": "security-audit-kit/evidence@1",
    "scan": {"command": "all", "exit_code": 1, "dimensions": [
        {"name": "sast", "status": "findings", "gate": "block"},
        {"name": "container", "status": "skipped", "gate": "allow"}]},
    "counts": {"total": 1, "by_severity": {"high": 1}, "by_decision": {"undecided": 1}},
    "findings": [{"id": "abc", "dimension": "sast", "tool": "semgrep", "rule_id": "py.sql", "file": "app.py",
                  "line": 3, "message": "<script>alert(1)</script>", "severity": "high",
                  "severity_source": "semgrep:level=error", "cvss": None, "decision": None, "confidence": None,
                  "evidence": None, "fingerprint": FP, "fingerprint_basis": "line-content",
                  "review": {"decision": "rejected", "owner": "<b>Ada</b>", "decided": "2026-11-01",
                             "reason": "only tests call it", "evidence_kind": "observed", "until": None,
                             "verify": None, "changed": []}}],
    "warnings": [],
}


DECISION = {"fingerprint": FP, "decision": "rejected", "evidence_kind": "observed", "reason": "only tests call it",
            "owner": "<b>Ada</b>", "decided": "2026-11-01", "until": None, "verify": None,
            "subject": {"rule_id": "py.sql", "file": "app.py"}}


def write_decisions(root, doc):
    p = root / "docs" / "security" / "decisions.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(doc if isinstance(doc, str) else json.dumps(doc))
    return p


def write_record(root, evidence=EVIDENCE, summary=None, decisions=True):
    d = root / "docs" / "security" / "scan-findings"
    d.mkdir(parents=True, exist_ok=True)
    if decisions and evidence is EVIDENCE:      # the live record agrees with the scan-time review
        write_decisions(root, {"schema": "security-audit-kit/decisions@1", "decisions": [DECISION]})
    if evidence is not None:
        (d / "evidence.json").write_text(evidence if isinstance(evidence, str) else json.dumps(evidence))
    if summary is not None:
        (d / "summary.json").write_text(json.dumps(summary))
    return d


@pytest.fixture
def repo(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    write_record(tmp_path)
    return tmp_path


@pytest.fixture
def ui(repo):
    u = us.UI(str(repo))
    t = threading.Thread(target=u.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    t.start()
    yield u
    u.server.shutdown()
    u.server.server_close()


def req(u, path, method="GET", host=None, cookie=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", u.port, timeout=5)
    h = {"Host": host if host is not None else u.host}
    if cookie:
        h["Cookie"] = cookie
    h.update(headers or {})
    c.request(method, path, headers=h)
    r = c.getresponse()
    body = r.read().decode("utf-8", "replace")
    out = (r.status, dict(r.getheaders()), body)
    c.close()
    return out


def login(u):
    status, headers, _ = req(u, f"/?t={u.token}")
    assert status == 303 and headers["Location"] == "/"
    return headers["Set-Cookie"].split(";")[0]


def test_binds_loopback_only(ui):
    assert ui.server.server_address[0] == "127.0.0.1" and ui.port > 0


def test_token_exchange_once_then_cookie(ui):
    status, headers, _ = req(ui, f"/?t={ui.token}")
    cookie = headers["Set-Cookie"]
    assert status == 303 and cookie.startswith(f"sak_ui_{ui.port}=")
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie and "Path=/" in cookie
    assert req(ui, f"/?t={ui.token}")[0] == 403                     # spent
    assert req(ui, "/", cookie=cookie.split(";")[0])[0] == 200


def test_wrong_token_and_no_cookie_are_refused(ui):
    assert req(ui, "/?t=wrong")[0] == 403
    assert req(ui, "/")[0] == 403
    assert req(ui, "/", cookie=f"sak_ui_{ui.port}=guess")[0] == 403
    # a session cookie for another port's server is not this one's
    cookie = login(ui)
    other = cookie.replace(f"sak_ui_{ui.port}=", "sak_ui_1=")
    assert req(ui, "/", cookie=other)[0] == 403


@pytest.mark.parametrize("host", ["localhost:{p}", "127.0.0.1", "evil.example", "127.0.0.1:{p}.evil.example", ""])
def test_host_must_be_exact(ui, host):
    assert req(ui, f"/?t={ui.token}", host=host.format(p=ui.port))[0] == 403
    assert not ui.token_spent


def test_only_get_and_head(ui):
    cookie = login(ui)
    for m in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
        assert req(ui, "/", method=m, cookie=cookie)[0] == 405
    status, headers, body = req(ui, "/", method="HEAD", cookie=cookie)
    assert status == 200 and body == "" and int(headers["Content-Length"]) > 0


def test_security_headers(ui):
    cookie = login(ui)
    _, h, _ = req(ui, "/", cookie=cookie)
    assert "frame-ancestors 'none'" in h["Content-Security-Policy"] and "default-src 'none'" in h["Content-Security-Policy"]
    assert h["X-Content-Type-Options"] == "nosniff" and h["Referrer-Policy"] == "no-referrer"
    assert h["Cache-Control"] == "no-store" and h["Cross-Origin-Opener-Policy"] == "same-origin"
    assert h["Cross-Origin-Resource-Policy"] == "same-origin"
    assert "Python" not in h.get("Server", "")


@pytest.mark.parametrize("path", ["/finding/../../etc/passwd", "/finding/ZZ", f"/finding/{FP}x", "/docs/security/scan-findings/evidence.json",
                                  "/%2e%2e/etc/passwd", "/favicon.ico"])
def test_no_file_serving_and_strict_routes(ui, path):
    cookie = login(ui)
    status, _, body = req(ui, path, cookie=cookie)
    assert status == 404 and "etc/passwd" not in body and "evidence" not in body.lower()


def test_index_escapes_hostile_text_and_links_the_finding(ui):
    cookie = login(ui)
    status, _, body = req(ui, "/", cookie=cookie)
    assert status == 200 and "<script>alert(1)</script>" not in body and "&lt;script&gt;" in body
    assert f'href="/finding/{FP}"' in body and "rejected by a person" in body
    assert "&lt;b&gt;Ada&lt;/b&gt;" in body


def test_detail_page(ui):
    cookie = login(ui)
    status, _, body = req(ui, f"/finding/{FP}", cookie=cookie)
    assert status == 200 and "py.sql" in body and "only tests call it" in body and "&lt;script&gt;" in body
    assert req(ui, "/finding/" + "cd" * 10, cookie=cookie)[0] == 404


def test_no_request_is_logged(ui, capsys):
    req(ui, f"/?t={ui.token}")
    req(ui, "/nope")
    out = capsys.readouterr()
    assert ui.token not in out.out + out.err


def test_a_missing_record_says_how_to_make_one(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    body = us.render_index(str(tmp_path), "2026-01-01")
    assert "no evidence.json yet" in body and "SARIF=1" in body


@pytest.mark.parametrize("content, why", [
    ("[1, 2]", "not a JSON object"),
    ('{"schema": "other"}', "unsupported evidence schema"),
    ("{" * 5000 + "}" * 5000, "not valid JSON"),
    ("\xff\xfe", "not valid JSON"),
])
def test_malformed_records_are_reported_not_crashed(tmp_path, content, why):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    write_record(tmp_path, content)
    body = us.render_index(str(tmp_path), "2026-01-01")
    assert why in body


def test_odd_fields_are_shaped_not_crashed(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    bad = dict(EVIDENCE, findings=[{"fingerprint": FP, "line": "3", "cvss": "9.8", "confidence": [1]},
                                   "not a dict", {"id": 7, "line": True, "review": "x", "evidence": [1]}],
               counts="nope", scan={"dimensions": "x"}, warnings="w")
    write_record(tmp_path, bad)
    body = us.render_index(str(tmp_path), "2026-01-01")
    assert "Security scan report" in body


def test_symlinks_and_size_are_refused(tmp_path, monkeypatch):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    outside = tmp_path.parent / (tmp_path.name + "-outside.json")
    outside.write_text(json.dumps(EVIDENCE))
    d = write_record(tmp_path, None)
    (d / "evidence.json").symlink_to(outside)
    assert "symbolic link" in us.render_index(str(tmp_path), "2026-01-01")
    (d / "evidence.json").unlink()
    # a symlinked directory on the way counts too
    real = tmp_path / "elsewhere"
    real.mkdir()
    (real / "evidence.json").write_text(json.dumps(EVIDENCE))
    os.rmdir(d)
    d.symlink_to(real)
    assert "symbolic link" in us.render_index(str(tmp_path), "2026-01-01")
    d.unlink()
    write_record(tmp_path)
    monkeypatch.setitem(us.CAPS, "evidence.json", 10)
    assert "limit" in us.render_index(str(tmp_path), "2026-01-01")


def test_a_tracked_record_is_flagged(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    write_record(tmp_path)
    g = ["git", "-C", str(tmp_path), "-c", "user.email=t@t", "-c", "user.name=t"]
    subprocess.run(g + ["add", "-f", "docs/security/scan-findings/evidence.json"], check=True)
    subprocess.run(g + ["commit", "-qm", "planted"], check=True)
    assert "tracked by git" in us.render_index(str(tmp_path), "2026-01-01")


def test_older_commit_running_scan_and_mismatched_pair(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    g = ["git", "-C", str(tmp_path), "-c", "user.email=t@t", "-c", "user.name=t"]
    subprocess.run(g + ["commit", "-q", "--allow-empty", "-m", "one"], check=True)
    ev = json.loads(json.dumps(EVIDENCE))
    ev["scan"]["provenance"] = {"commit": "0" * 40, "dirty": False}
    write_record(tmp_path, ev, summary={"dimensions": [{"name": "secret", "status": "pass"}], "timestamp": "2026-01-01T00:00:00"})
    lock = tmp_path / ".git" / "security-audit-cache" / "scan.lock"
    lock.mkdir(parents=True)
    (lock / "owner").write_text("pid=42\ncmd=all\ndate=2026-11-23T10:00:00\n")
    body = us.render_index(str(tmp_path), "2026-01-01")
    assert "older commit" in body and "A scan is running (all" in body and "not from the run in summary.json" in body


def test_the_ui_writes_nothing(ui, repo):
    before = sorted(str(p) for p in repo.rglob("*") if ".git" not in p.parts)
    cookie = login(ui)
    req(ui, "/", cookie=cookie)
    req(ui, f"/finding/{FP}", cookie=cookie)
    assert sorted(str(p) for p in repo.rglob("*") if ".git" not in p.parts) == before


def test_idle_stop(repo):
    u = us.UI(str(repo), idle_sec=1)
    t = threading.Thread(target=u.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    t.start()
    u.last -= 5
    u.watch_idle()                    # returns once it has stopped the server
    t.join(timeout=5)
    assert not t.is_alive()
    u.server.server_close()


# ---------------------------------------------------------------------------------------------
# R13b: start and cancel a scan. A fake scan.sh records its argv and env, prints, sleeps, publishes
# a summary.json whose run_id ends in its own pid (as scan.sh's RUN_ID does) and exits as told.
# ---------------------------------------------------------------------------------------------
import signal as _signal  # noqa: E402
import time as _time  # noqa: E402
import urllib.parse as _up  # noqa: E402

FAKE = r'''#!/usr/bin/env bash
k="$(cd "$(dirname "$0")" && pwd)"
printf '%s\n' "$@" > "$k/argv"; env > "$k/env"
read -r sleep rc publish < "$k/behave"
trap 'echo cancelled; exit 130' INT
echo "── scanning $1"
printf '\033[31mred\033[0m <b>bold</b>\n'
[ "$rc" = lock ] && { echo "could not take the lock -> not run (SCAN_LOCK_BUSY=exit)"; exit 1; }
i=0; while [ "$i" -lt "$sleep" ]; do sleep 0.1; i=$((i+1)); done
[ "$publish" = 1 ] && printf '{"run_id": "20260101T000000-%s", "dimensions": [{"name": "container", "status": "skipped"}]}\n' "$$" > "$PWD/docs/security/scan-findings/summary.json"
exit "$rc"
'''


@pytest.fixture
def runui(repo, tmp_path_factory, monkeypatch):
    kit = tmp_path_factory.mktemp("kit")
    (kit / "scan.sh").write_text(FAKE)
    (kit / "behave").write_text("0 0 1\n")
    monkeypatch.setattr(us, "integrity", lambda root, k: (True, ""))
    monkeypatch.setenv("SKIP_SECURITY", "1")
    monkeypatch.setenv("GATE_STRICT", "1")
    monkeypatch.setattr(us, "CANCEL_TERM_SEC", 1)
    monkeypatch.setattr(us, "CANCEL_KILL_SEC", 2)
    u = us.UI(str(repo), kit=str(kit))
    t = threading.Thread(target=u.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    t.start()
    u.kitdir = kit
    yield u
    if u.job is not None and u.job.state == "running":
        u.job.cancel()
        u.job.proc.wait(timeout=10)
    u.server.shutdown()
    u.server.server_close()


def post(u, path, fields, cookie, origin="same", ctype="application/x-www-form-urlencoded", sfs=None, body=None):
    data = body if body is not None else _up.urlencode(fields)
    h = {"Content-Type": ctype}
    if origin == "same":
        h["Origin"] = f"http://{u.host}"
    elif origin is not None:
        h["Origin"] = origin
    if sfs:
        h["Sec-Fetch-Site"] = sfs
    c = http.client.HTTPConnection("127.0.0.1", u.port, timeout=5)
    c.request("POST", path, body=data, headers=dict(h, Host=u.host, Cookie=cookie))
    r = c.getresponse()
    out = (r.status, dict(r.getheaders()), r.read().decode("utf-8", "replace"))
    c.close()
    return out


def wait_end(u, timeout=10):
    end = _time.time() + timeout
    while u.job.state == "running" and _time.time() < end:
        _time.sleep(0.05)
    return u.job.state


def test_index_has_the_run_form_with_form_action_self(runui):
    cookie = login(runui)
    status, h, body = req(runui, "/", cookie=cookie)
    assert 'action="/run"' in body and f'value="{runui.form_token}"' in body
    assert "form-action 'self'" in h["Content-Security-Policy"] and h["Referrer-Policy"] == "same-origin"
    assert '<option value="fast">' in body and '<option value="all">' in body and "zizmor" not in body


def test_start_runs_the_fixed_command_with_the_built_env(runui):
    cookie = login(runui)
    status, h, _ = post(runui, "/run", {"ft": runui.form_token, "cmd": "fast"}, cookie)
    assert status == 303 and h["Location"] == "/run"
    assert wait_end(runui) == "passed"
    assert (runui.kitdir / "argv").read_text().split() == ["fast"]
    env = dict(line.split("=", 1) for line in (runui.kitdir / "env").read_text().splitlines() if "=" in line)
    assert "SKIP_SECURITY" not in env and env["GATE_STRICT"] == "1"
    assert env["SARIF"] == "1" and env["REPORT"] == "html" and env["SCAN_LOCK_BUSY"] == "exit"
    assert runui.job.published()
    _, _, page_ = req(runui, "/run", cookie=cookie)
    assert "passed" in page_ and "this run" in page_ and "container (skipped)" in page_
    assert "&lt;b&gt;bold&lt;/b&gt;" in page_ and "\x1b" not in page_ and "<b>bold</b>" not in page_


def test_stdin_is_not_the_servers(runui):
    cookie = login(runui)
    post(runui, "/run", {"ft": runui.form_token, "cmd": "fast"}, cookie)
    wait_end(runui)
    assert runui.job.proc.stdin is None          # DEVNULL: Popen keeps no handle


def test_one_run_at_a_time_and_cancel(runui):
    (runui.kitdir / "behave").write_text("200 0 1\n")
    cookie = login(runui)
    assert post(runui, "/run", {"ft": runui.form_token, "cmd": "all"}, cookie)[0] == 303
    _time.sleep(0.3)
    assert post(runui, "/run", {"ft": runui.form_token, "cmd": "fast"}, cookie)[0] == 409
    _, _, running = req(runui, "/run", cookie=cookie)
    assert 'http-equiv="refresh"' in running and 'action="/run/cancel"' in running
    _, _, index = req(runui, "/", cookie=cookie)
    assert "A scan started here is running" in index
    assert post(runui, "/run/cancel", {"ft": runui.form_token}, cookie)[0] == 303
    assert wait_end(runui) == "cancelled" and runui.job.rc == 130 and not runui.job.published()
    _, _, done = req(runui, "/run", cookie=cookie)
    assert "nothing was published" in done and "not updated by this run" in done


def test_a_scan_that_ignores_sigint_is_killed(runui):
    (runui.kitdir / "scan.sh").write_text(FAKE.replace("trap 'echo cancelled; exit 130' INT", "trap '' INT TERM"))
    (runui.kitdir / "behave").write_text("300 0 0\n")
    cookie = login(runui)
    post(runui, "/run", {"ft": runui.form_token, "cmd": "all"}, cookie)
    _time.sleep(0.3)
    post(runui, "/run/cancel", {"ft": runui.form_token}, cookie)
    assert wait_end(runui, 15) == "killed"
    assert "killed" in req(runui, "/run", cookie=cookie)[2]


def test_lock_busy_is_not_started_and_blocked_is_blocked(runui):
    (runui.kitdir / "behave").write_text("0 lock 0\n")
    cookie = login(runui)
    post(runui, "/run", {"ft": runui.form_token, "cmd": "all"}, cookie)
    assert wait_end(runui) == "not started"
    (runui.kitdir / "behave").write_text("0 1 1\n")
    post(runui, "/run", {"ft": runui.form_token, "cmd": "all"}, cookie)
    assert wait_end(runui) == "blocked" and runui.job.published()


def test_cancel_after_the_run_published(runui):
    cookie = login(runui)
    post(runui, "/run", {"ft": runui.form_token, "cmd": "fast"}, cookie)
    wait_end(runui)
    runui.job.cancel_requested = True
    assert "already finished and published" in req(runui, "/run", cookie=cookie)[2]


@pytest.mark.parametrize("kw, code", [
    ({"origin": None}, 403),
    ({"origin": "null"}, 403),
    ({"origin": "http://127.0.0.1:1"}, 403),
    ({"origin": "http://localhost:{p}"}, 403),
    ({"sfs": "same-site"}, 403),
    ({"sfs": "cross-site"}, 403),
    ({"ctype": "text/plain"}, 415),
    ({"ctype": "multipart/form-data"}, 415),
    ({"body": "ft=x&cmd=fast&cmd=all"}, 400),
    ({"body": "ft=x&cmd=fast&extra=1"}, 400),
    ({"body": "&&&"}, 400),
    ({"body": "x" * 2000}, 413),
])
def test_cross_site_and_malformed_posts_are_refused(runui, kw, code):
    cookie = login(runui)
    if "origin" in kw and kw["origin"] and "{p}" in kw["origin"]:
        kw["origin"] = kw["origin"].format(p=runui.port)
    status, _, _ = post(runui, "/run", {"ft": runui.form_token, "cmd": "fast"}, cookie, **kw)
    assert status == code and runui.job is None


def test_form_token_session_and_command_table(runui):
    cookie = login(runui)
    assert post(runui, "/run", {"ft": "wrong", "cmd": "fast"}, cookie)[0] == 403
    assert post(runui, "/run", {"cmd": "fast"}, cookie)[0] == 400
    assert post(runui, "/run", {"ft": runui.form_token, "cmd": "zizmor"}, cookie)[0] == 400
    assert post(runui, "/run", {"ft": runui.form_token, "cmd": "all; rm -rf /"}, cookie)[0] == 400
    assert post(runui, "/run", {"ft": runui.form_token, "cmd": "fast"}, f"sak_ui_{runui.port}=nope")[0] == 403
    assert post(runui, "/", {"ft": runui.form_token, "cmd": "fast"}, cookie)[0] == 405
    assert runui.job is None


def test_post_needs_content_length(runui):
    cookie = login(runui)
    c = http.client.HTTPConnection("127.0.0.1", runui.port, timeout=5)
    c.putrequest("POST", "/run", skip_host=True)
    for k, v in {"Host": runui.host, "Cookie": cookie, "Origin": f"http://{runui.host}",
                 "Content-Type": "application/x-www-form-urlencoded"}.items():
        c.putheader(k, v)
    c.endheaders()
    assert c.getresponse().status == 413 and runui.job is None


def test_integrity_failure_refuses_to_start(runui, monkeypatch):
    monkeypatch.setattr(us, "integrity", lambda root, k: (False, "the vendored kit is not the one installed here: MODIFIED scan.sh"))
    cookie = login(runui)
    status, _, body = post(runui, "/run", {"ft": runui.form_token, "cmd": "fast"}, cookie)
    assert status == 409 and "MODIFIED scan.sh" in body and runui.job is None


def test_real_integrity_without_an_install_record(repo, tmp_path):
    ok, why = us.integrity(str(repo), str(tmp_path))
    assert not ok and "no install record" in why


def test_no_kit_means_no_form(ui):
    cookie = login(ui)
    _, h, body = req(ui, "/", cookie=cookie)
    assert 'action="/run"' not in body and "form-action 'none'" in h["Content-Security-Policy"]
    assert post(ui, "/run", {"ft": ui.form_token, "cmd": "fast"}, cookie)[0] == 409


def test_idle_stop_waits_for_a_running_scan(runui):
    (runui.kitdir / "behave").write_text("30 0 0\n")
    cookie = login(runui)
    post(runui, "/run", {"ft": runui.form_token, "cmd": "fast"}, cookie)
    runui.idle_sec = 1
    runui.last -= 100
    t = threading.Thread(target=runui.watch_idle, daemon=True)
    t.start()
    t.join(timeout=2)
    assert t.is_alive()                  # still waiting: the scan runs
    wait_end(runui)
    t.join(timeout=5)
    assert not t.is_alive()


def test_a_stale_lock_is_not_a_running_scan(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    lock = tmp_path / ".git" / "security-audit-cache" / "scan.lock"
    lock.mkdir(parents=True)
    import socket as _socket
    p = subprocess.Popen(["true"]); p.wait()
    (lock / "owner").write_text(f"pid={p.pid}\nhost={_socket.gethostname()}\ncmd=all\ndate=x\n")
    assert us.lock_owner(str(tmp_path)) is None
    (lock / "owner").write_text(f"pid={os.getpid()}\nhost={_socket.gethostname()}\ncmd=all\ndate=x\n")
    assert us.lock_owner(str(tmp_path))["cmd"] == "all"
    (lock / "owner").write_text("pid=1\nhost=another-machine\ncmd=all\ndate=x\n")
    assert us.lock_owner(str(tmp_path)) is not None


# ---------------------------------------------------------------------------------------------
# R13c: a person's decision written from the page, through scan.sh decide. The fake scan.sh does
# what scan_decide does (decisions.py with the fixed paths) unless told to refuse, hang or fail.
LIB = os.path.join(os.path.dirname(__file__), "..", "..", "lib")
FAKE_DECIDE = r'''#!/usr/bin/env bash
k="$(cd "$(dirname "$0")" && pwd)"
printf '%s\n' "$@" > "$k/argv"; env > "$k/env"
mode="$(cat "$k/mode")"
[ "$1" = decide ] || exit 9
shift
case "$mode" in
  refuse) echo "decide: REFUSED — --until 2020-01-01 is not in the future" >&2; exit 2 ;;
  hang)   sleep 30; exit 0 ;;
  odd)    echo "something else"; exit 5 ;;
esac
D="$PWD/docs/security/decisions.json"; E="$PWD/docs/security/scan-findings/evidence.json"
[ "$1" = remove ] && exec python3 "__LIB__/decisions.py" remove "$D" "$2"
fp="$1" d="$2"; shift 2
exec python3 "__LIB__/decisions.py" set "$D" "$E" "$fp" "$d" "$@"
'''
NOREVIEW = json.loads(json.dumps(EVIDENCE))
NOREVIEW["findings"][0].pop("review")


@pytest.fixture
def dui(tmp_path, tmp_path_factory, monkeypatch):
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    write_record(repo, evidence=NOREVIEW)
    kit = tmp_path_factory.mktemp("kit")
    (kit / "scan.sh").write_text(FAKE_DECIDE.replace("__LIB__", os.path.abspath(LIB)))
    (kit / "mode").write_text("real")
    monkeypatch.setattr(us, "integrity", lambda root, k: (True, ""))
    monkeypatch.setattr(us, "DECIDE_TIMEOUT", 1)
    u = us.UI(str(repo), kit=str(kit))
    threading.Thread(target=u.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    u.kitdir, u.repo = kit, repo
    yield u
    u.server.shutdown()
    u.server.server_close()


def dform(u, **kw):
    f = {"ft": u.form_token, "fp": FP, "decision": "rejected", "evidence_kind": "observed",
         "reason": "only tests call it", "until": "", "verify": "", "owner": "Ada"}
    f.update(kw)
    return {k: v for k, v in f.items() if v is not None}


def live(u):
    p = u.repo / "docs" / "security" / "decisions.json"
    return json.loads(p.read_text())["decisions"] if p.exists() else []


def test_finding_page_carries_the_decision_form_as_a_form_page(dui):
    cookie = login(dui)
    status, h, body = req(dui, f"/finding/{FP}", cookie=cookie)
    assert status == 200 and 'action="/decide"' in body and 'action="/decide/remove"' not in body
    assert h["Referrer-Policy"] == "same-origin" and "form-action 'self'" in h["Content-Security-Policy"]
    assert "form-action &#x27;self&#x27;" in body or "form-action 'self'" in body
    assert "never changes what blocks a push" in body


def test_set_runs_decide_with_opt_value_argv_and_shows_it_live(dui):
    cookie = login(dui)
    status, h, _ = post(dui, "/decide", dform(dui, reason="-x --owner=evil", until="", verify=""), cookie)
    assert status == 303 and h["Location"] == f"/finding/{FP}"
    argv = (dui.kitdir / "argv").read_text().splitlines()
    assert argv == ["decide", FP, "rejected", "--reason=-x --owner=evil", "--evidence-kind=observed", "--owner=Ada"]
    assert "PYTHONUTF8=1" in (dui.kitdir / "env").read_text()
    [d] = live(dui)
    assert d["reason"] == "-x --owner=evil" and d["owner"] == "Ada"
    body = req(dui, f"/finding/{FP}", cookie=cookie)[2]
    assert "recorded" in body and "-x --owner=evil" in body and "Replace decision" in body
    assert "evidence.json is updated by the next scan" in body
    # the notice is shown once
    assert "decide: recorded" not in req(dui, f"/finding/{FP}", cookie=cookie)[2]
    assert "rejected by a person" in req(dui, "/", cookie=cookie)[2]


def test_the_notice_is_not_consumed_by_head_or_another_page(dui):
    cookie = login(dui)
    assert post(dui, "/decide", dform(dui), cookie)[0] == 303
    req(dui, f"/finding/{FP}", method="HEAD", cookie=cookie)
    req(dui, "/", cookie=cookie)
    req(dui, "/finding/" + "cd" * 10, cookie=cookie)
    assert "decide: recorded" in req(dui, f"/finding/{FP}", cookie=cookie)[2]


def test_remove_takes_the_decision_away_even_though_evidence_has_it(dui):
    cookie = login(dui)
    assert post(dui, "/decide", dform(dui), cookie)[0] == 303
    # evidence.json now carries the scan-time review too, as after a rescan
    write_record(dui.repo, evidence=EVIDENCE, decisions=False)
    status, h, _ = post(dui, "/decide/remove", {"ft": dui.form_token, "fp": FP}, cookie)
    assert status == 303 and live(dui) == []
    body = req(dui, f"/finding/{FP}", cookie=cookie)[2]
    assert "Removed: rejected · only tests call it · Ada" in body and "only copy" in body
    assert "A person&#x27;s decision" not in body and "A person's decision" not in body
    assert "rejected by a person" not in req(dui, "/", cookie=cookie)[2]
    assert post(dui, "/decide/remove", {"ft": dui.form_token, "fp": FP}, cookie)[0] == 409


def test_browser_shaped_body_with_blank_fields_is_accepted(dui):
    cookie = login(dui)
    body = f"ft={dui.form_token}&fp={FP}&decision=confirmed&reason=real&evidence_kind=unverified&until=&owner=&verify="
    status, _, page_ = post(dui, "/decide", None, cookie, body=body)
    argv = (dui.kitdir / "argv").read_text().splitlines()
    assert not any(a.startswith(("--owner", "--until", "--verify")) for a in argv)
    # the fake does not add git's user.name as scan_decide does, so decisions.py asks for an owner
    assert status == 422 and "--owner is required" in page_ and "real</textarea>" in page_
    assert post(dui, "/decide", None, cookie, body=body.replace("owner=", "owner=Ada"))[0] == 303


def test_missing_decision_and_refusal_keep_the_typed_text(dui):
    cookie = login(dui)
    status, h, body = post(dui, "/decide", dform(dui, decision=None, reason="my long reason"), cookie)
    assert status == 422 and "Choose a decision" in body and "my long reason" in body
    assert h["Referrer-Policy"] == "same-origin" and not (dui.kitdir / "argv").exists()
    status, _, body = post(dui, "/decide", dform(dui, until="tomorrow", reason="kept"), cookie)
    assert status == 422 and "YYYY-MM-DD" in body and "kept" in body
    (dui.kitdir / "mode").write_text("refuse")
    status, _, body = post(dui, "/decide", dform(dui, decision="accepted", until="2020-01-01", reason="kept <b>"), cookie)
    assert status == 422 and "not in the future" in body and "kept &lt;b&gt;" in body and 'value="2020-01-01"' in body
    assert live(dui) == []


def test_timeout_kills_the_group_and_says_it_may_have_been_written(dui):
    (dui.kitdir / "mode").write_text("hang")
    cookie = login(dui)
    t0 = _time.time()
    status, _, body = post(dui, "/decide", dform(dui), cookie)
    assert status == 500 and "may have been written" in body and _time.time() - t0 < 10
    (dui.kitdir / "mode").write_text("odd")
    status, _, body = post(dui, "/decide", dform(dui), cookie)
    assert status == 500 and "exited 5" in body


@pytest.mark.parametrize("fp", ["ababababab", "AB" * 10, "ab" * 9 + "a", "ab" * 10 + "a", "../" * 7, "cd" * 10])
def test_fingerprint_shape_and_presence(dui, fp):
    cookie = login(dui)
    status = post(dui, "/decide", dform(dui, fp=fp), cookie)[0]
    assert status in (400, 409) and not (dui.kitdir / "argv").exists()


@pytest.mark.parametrize("body, code", [
    ("ft={ft}&fp={fp}&decision=rejected&reason=x&evidence_kind=observed&until=&verify=&owner=&cmd=fast", 400),
    ("ft={ft}&fp={fp}&decision=rejected&decision=confirmed&reason=x&evidence_kind=observed&until=&verify=&owner=", 400),
    ("ft={ft}&fp={fp}&decision=rejected&reason=x&evidence_kind=observed", 400),           # fields missing
    ("ft={ft}&fp={fp}&decision=rejected&reason=%ff&evidence_kind=observed&until=&verify=&owner=", 400),
    ("ft={ft}&fp={fp}&decision=rejected&reason=a%00b&evidence_kind=observed&until=&verify=&owner=", 400),
    ("ft={ft}&fp={fp}&decision=rejected&reason=x&evidence_kind=proven&until=&verify=&owner=", 400),
    ("ft=wrong&fp={fp}&decision=rejected&reason=x&evidence_kind=observed&until=&verify=&owner=", 403),
    ("ft={ft}&fp={fp}&reason=" + "x" * (64 << 10), 413),
])
def test_malformed_decide_posts_are_refused(dui, body, code):
    cookie = login(dui)
    assert post(dui, "/decide", None, cookie, body=body.format(ft=dui.form_token, fp=FP))[0] == code
    assert not (dui.kitdir / "argv").exists()


@pytest.mark.parametrize("kw", [{"origin": None}, {"origin": "null"}, {"origin": "http://127.0.0.1:1"}, {"sfs": "cross-site"}])
def test_cross_site_decide_is_refused(dui, kw):
    cookie = login(dui)
    assert post(dui, "/decide", dform(dui), cookie, **kw)[0] == 403
    assert post(dui, "/decide", dform(dui), f"sak_ui_{dui.port}=nope")[0] == 403
    assert not (dui.kitdir / "argv").exists()


def test_non_ascii_reason_fits_the_cap(dui):
    cookie = login(dui)
    reason = "ğüşiöç🔒" * 250                     # 2000 characters, multi-byte
    assert post(dui, "/decide", dform(dui, reason=reason), cookie)[0] == 303
    assert live(dui)[0]["reason"] == reason


def test_preconditions_refuse_before_anything_runs(dui, monkeypatch, tmp_path):
    cookie = login(dui)
    monkeypatch.setattr(us, "integrity", lambda root, k: (False, "MODIFIED scan.sh"))
    status, _, body = post(dui, "/decide", dform(dui, reason="keep me"), cookie)
    assert status == 409 and "MODIFIED scan.sh" in body and "keep me" in body
    monkeypatch.setattr(us, "integrity", lambda root, k: (True, ""))
    # a branch-authored record that validates loosely but would crash the old code
    write_decisions(dui.repo, {"schema": "security-audit-kit/decisions@1", "decisions": [dict(DECISION, subject={"package": "x"})]})
    status, _, body = req(dui, f"/finding/{FP}", cookie=cookie)
    assert status == 200 and "decisions.json not used" in body and 'action="/decide"' not in body
    assert req(dui, "/", cookie=cookie)[0] == 200
    assert post(dui, "/decide", dform(dui), cookie)[0] == 409
    # a symlinked file, then a symlinked directory: decisions.py would follow either
    p = dui.repo / "docs" / "security" / "decisions.json"
    p.unlink()
    outside = tmp_path / "outside.json"
    outside.write_text('{"schema": "security-audit-kit/decisions@1", "decisions": []}')
    p.symlink_to(outside)
    assert post(dui, "/decide", dform(dui), cookie)[0] == 409
    p.unlink()
    assert not (dui.kitdir / "argv").exists()


def test_symlinked_docs_security_is_refused(tmp_path, tmp_path_factory, monkeypatch):
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    elsewhere = tmp_path / "elsewhere"
    write_record(elsewhere, evidence=NOREVIEW)
    (repo / "docs").mkdir()
    (repo / "docs" / "security").symlink_to(elsewhere / "docs" / "security")
    kit = tmp_path_factory.mktemp("kit")
    (kit / "scan.sh").write_text(FAKE_DECIDE.replace("__LIB__", os.path.abspath(LIB)))
    (kit / "mode").write_text("real")
    monkeypatch.setattr(us, "integrity", lambda root, k: (True, ""))
    u = us.UI(str(repo), kit=str(kit))
    ok, why = u.decide_ready()
    assert not ok and "symbolic link" in why
    u.server.server_close()


def test_git_banners_for_uncommitted_and_ignored(dui):
    cookie = login(dui)
    assert post(dui, "/decide", dform(dui), cookie)[0] == 303
    assert "new and not yet added" in req(dui, f"/finding/{FP}", cookie=cookie)[2]
    (dui.repo / ".gitignore").write_text("docs/security/decisions.json\n")
    assert "ignored by git" in req(dui, f"/finding/{FP}", cookie=cookie)[2]


def test_scan_time_warnings_about_decisions_are_replaced_by_live_ones(dui):
    ev = json.loads(json.dumps(NOREVIEW))
    ev["warnings"] = ["3 decision(s) in decisions.json are about findings this scan did not report (fixed) — x",
                      "decisions.json not used: broken", "an unrelated builder note"]
    write_record(dui.repo, evidence=ev)
    cookie = login(dui)
    body = req(dui, "/", cookie=cookie)[2]
    assert "an unrelated builder note" in body and "3 decision(s)" not in body and "not used: broken" not in body
