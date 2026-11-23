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


def write_record(root, evidence=EVIDENCE, summary=None):
    d = root / "docs" / "security" / "scan-findings"
    d.mkdir(parents=True, exist_ok=True)
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
