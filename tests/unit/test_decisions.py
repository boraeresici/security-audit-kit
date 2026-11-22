"""F19a slice 3: the decision record. Only `decide` writes it, it stays valid and diffable, and a
decision says what it was about even after the finding changes name."""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "lib"))

import decisions  # noqa: E402

FP1 = "a" * 20
FP2 = "ab" + "c" * 18
FP3 = "ab" + "d" * 18


def evidence(tmp_path, *rows):
    p = tmp_path / "evidence.json"
    p.write_text(json.dumps({"schema": "security-audit-kit/evidence@1", "findings": list(rows)}))
    return str(p)


def row(fp, rule="CVE-2021-33503", tool="osv-scanner", **kw):
    r = {"fingerprint": fp, "fingerprint_basis": "package", "dimension": "osv", "tool": tool, "rule_id": rule,
         "file": "requirements.txt", "line": None, "message": "urllib3 is vulnerable",
         "package": {"ecosystem": "pypi", "name": "urllib3", "version": "1.26.4"}}
    r.update(kw)
    return r


def run(*argv):
    return decisions.main([str(a) for a in argv])


@pytest.fixture
def env(tmp_path):
    ev = evidence(tmp_path, row(FP1, aliases=["GHSA-q2q7-5pp4-w6pg", "PYSEC-2021-108"]),
                  row(FP1, tool="trivy"), row(FP2, rule="py.sql", file="app/db.py", line=4, package=None),
                  row(FP3, rule="py.sql", file="app/db.py", line=9, package=None))
    return tmp_path, str(tmp_path / "docs" / "security" / "decisions.json"), ev


def read(path):
    return json.load(open(path, encoding="utf-8"))


def test_a_decision_is_recorded_with_the_finding_as_it_was(env, capsys):
    _, rec, ev = env
    assert run("set", rec, ev, FP1, "rejected", "--reason", "not reachable: the parser is never called",
               "--owner", "Ada", "--evidence-kind", "observed", "--date", "2026-11-22") == 0
    d = read(rec)
    assert d["schema"] == decisions.SCHEMA and len(d["decisions"]) == 1
    e = d["decisions"][0]
    assert (e["fingerprint"], e["decision"], e["owner"], e["decided"], e["evidence_kind"]) == (FP1, "rejected", "Ada", "2026-11-22", "observed")
    s = e["subject"]
    assert s["tools"] == ["osv-scanner", "trivy"]                    # one advisory, two tools, one decision
    assert s["aliases"] == ["CVE-2021-33503", "GHSA-q2q7-5pp4-w6pg", "PYSEC-2021-108"]
    assert s["package"] == {"ecosystem": "pypi", "name": "urllib3", "version": "1.26.4"}
    assert "does not change what blocks a push" in capsys.readouterr().out


def test_a_second_decision_replaces_the_first_and_the_file_is_sorted_and_stable(env):
    _, rec, ev = env
    run("set", rec, ev, FP2, "confirmed", "--reason", "r", "--owner", "A", "--date", "2026-11-22")
    run("set", rec, ev, FP1, "rejected", "--reason", "r", "--owner", "A", "--date", "2026-11-22")
    first = open(rec, encoding="utf-8").read()
    run("set", rec, ev, FP2, "confirmed", "--reason", "r", "--owner", "A", "--date", "2026-11-22")
    assert open(rec, encoding="utf-8").read() == first                 # same decision again: same bytes
    run("set", rec, ev, FP2, "needs-validation", "--reason", "r", "--owner", "A", "--verify", "run it against prod data",
        "--date", "2026-11-22")
    d = read(rec)["decisions"]
    assert [x["fingerprint"] for x in d] == sorted([FP1, FP2]) and d[1]["decision"] == "needs-validation"
    assert first.endswith("}\n") and "\t" not in first


def test_a_unique_prefix_works_and_an_ambiguous_or_unknown_one_is_refused(env, capsys):
    _, rec, ev = env
    assert run("set", rec, ev, FP1[:8], "confirmed", "--reason", "r", "--owner", "A") == 0
    assert run("set", rec, ev, "abcccccc", "confirmed", "--reason", "r", "--owner", "A") == 0
    assert run("set", rec, ev, "abcd1234", "confirmed", "--reason", "r", "--owner", "A") == 2        # no such finding
    assert run("set", rec, ev, "ab", "confirmed", "--reason", "r", "--owner", "A") == 2              # too short
    assert run("set", rec, ev, "ab" + "c" * 2 + "d", "confirmed", "--reason", "r", "--owner", "A") == 2
    err = capsys.readouterr().err
    assert "REFUSED" in err and "no finding" in err
    assert len(read(rec)["decisions"]) == 2


def test_only_findings_in_the_current_evidence_can_be_decided(env, capsys):
    _, rec, ev = env
    assert run("set", rec, ev, "f" * 20, "rejected", "--reason", "r", "--owner", "A") == 2
    assert "not in the current evidence.json" in capsys.readouterr().err
    assert not os.path.exists(rec)
    assert run("set", rec, ev + ".missing", FP1, "rejected", "--reason", "r", "--owner", "A") == 2


@pytest.mark.parametrize("args, why", [
    (["rejected"], "--reason is required"),
    (["rejected", "--reason", "   "], "--reason is required"),
    (["maybe", "--reason", "r"], "decision must be one of"),
    (["accepted", "--reason", "r"], "needs --until"),
    (["accepted", "--reason", "r", "--until", "2026-11-21"], "not in the future"),
    (["accepted", "--reason", "r", "--until", "2028-01-01"], "within 366 days"),
    (["accepted", "--reason", "r", "--until", "2026-13-01"], "not a date"),
    (["accepted", "--reason", "r", "--until", "next week"], "expected YYYY-MM-DD"),
    (["needs-validation", "--reason", "r"], "needs --verify"),
    (["rejected", "--reason", "x" * 2001], "at most 2000"),
])
def test_what_the_record_refuses(env, capsys, args, why):
    _, rec, ev = env
    owner = [] if "--owner" in args else ["--owner", "A"]
    assert run("set", rec, ev, FP1, *args, *owner, "--date", "2026-11-22") == 2
    assert why in capsys.readouterr().err
    assert not os.path.exists(rec)


def test_no_owner_is_refused(env, capsys):
    _, rec, ev = env
    assert run("set", rec, ev, FP1, "confirmed", "--reason", "r") == 2
    assert "--owner is required" in capsys.readouterr().err


def test_text_is_one_clean_line(env):
    _, rec, ev = env
    run("set", rec, ev, FP1, "rejected", "--reason", "line one\nline‮ two\x1b[31m​", "--owner", "A\tB",
        "--date", "2026-11-22")
    e = read(rec)["decisions"][0]
    assert e["reason"] == "line one line two [31m" and e["owner"] == "A B"


def test_a_broken_or_foreign_record_is_refused_not_replaced(env, capsys):
    tmp, rec, ev = env
    os.makedirs(os.path.dirname(rec))
    for text in ("{not json", json.dumps({"schema": "other", "decisions": []}),
                 json.dumps({"schema": decisions.SCHEMA, "decisions": [{"fingerprint": FP1}]})):
        open(rec, "w").write(text)
        assert run("set", rec, ev, FP2, "confirmed", "--reason", "r", "--owner", "A") == 2
        assert open(rec).read() == text
    assert "REFUSED" in capsys.readouterr().err


def test_validate_names_each_problem():
    good = {"fingerprint": FP1, "decision": "accepted", "evidence_kind": "observed", "reason": "r", "owner": "A",
            "decided": "2026-11-22", "until": "2027-01-01", "subject": {}}
    assert decisions.validate({"schema": decisions.SCHEMA, "decisions": [good]}) == []
    bad = dict(good, until=None)
    dup = {"schema": decisions.SCHEMA, "decisions": [good, good, bad, dict(good, fingerprint="xyz", evidence_kind="vibes")]}
    problems = " | ".join(decisions.validate(dup))
    assert "decided twice" in problems and "needs an until" in problems and "20 hex" in problems and "evidence_kind" in problems


def test_remove_list_and_check(env, capsys):
    tmp, rec, ev = env
    run("set", rec, ev, FP1, "accepted", "--reason", "r", "--owner", "A", "--until", "2026-12-01", "--date", "2026-11-22")
    run("set", rec, ev, FP2, "confirmed", "--reason", "r", "--owner", "A", "--date", "2026-11-22")
    capsys.readouterr()
    # FP2's finding was fixed: the next evidence no longer has it
    ev2 = evidence(tmp, row(FP1))
    assert run("list", rec, ev2) == 0
    out = capsys.readouterr().out
    assert "accepted" in out and "not-seen" in out
    # time passes: the accepted risk expires and check says so
    data = read(rec)
    data["decisions"][0]["until"] = "2020-01-01"
    open(rec, "w").write(json.dumps(data))
    assert run("check", rec) == 1
    assert "expired 2020-01-01" in capsys.readouterr().out
    assert run("remove", rec, FP1[:10]) == 0
    assert [d["fingerprint"] for d in read(rec)["decisions"]] == [FP2]
    assert run("remove", rec, "f" * 20) == 2
    assert run("check", rec) == 0


def test_an_empty_or_missing_record(tmp_path, capsys):
    rec = str(tmp_path / "decisions.json")
    assert run("list", rec) == 0 and "no decisions" in capsys.readouterr().out
    assert run("check", rec) == 0
