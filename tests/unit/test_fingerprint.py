"""F19a slice 1: the fingerprint survives what does not change a finding, and only that.

Each case is one of the card's fixtures: a line shift, the same line twice, the same advisory in
two packages, a version bump; plus the paths the reader must refuse.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "lib"))

import fingerprint  # noqa: E402


def code(line, rule="py.sql", path="app/db.py", dim="sast"):
    return {"id": "x", "dimension": dim, "tool": "semgrep", "rule_id": rule, "file": path, "line": line}


def dep(name, version, rule="PYSEC-2021-108", eco="pypi", path=None):
    return {"id": "x", "dimension": "py-deps", "tool": "pip-audit", "rule_id": rule, "file": path, "line": None,
            "package": {"ecosystem": eco, "name": name, "version": version}}


def write(root, path, text):
    full = os.path.join(root, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as fh:
        fh.write(text)


def fp(root, *findings):
    fs = [dict(f) for f in findings]
    fingerprint.assign(fs, str(root))
    return fs


def test_line_shift_keeps_the_fingerprint(tmp_path):
    write(tmp_path, "app/db.py", "import db\ncur.execute(q % user)\n")
    before = fp(tmp_path, code(2))[0]
    write(tmp_path, "app/db.py", "import db\n\n# a comment\ncur.execute(q % user)\n")
    after = fp(tmp_path, code(4))[0]
    assert before["fingerprint_basis"] == after["fingerprint_basis"] == "line-content"
    assert before["fingerprint"] == after["fingerprint"]


def test_reindenting_keeps_it_and_editing_changes_it(tmp_path):
    write(tmp_path, "app/db.py", "cur.execute(q % user)\n")
    a = fp(tmp_path, code(1))[0]["fingerprint"]
    write(tmp_path, "app/db.py", "    cur.execute(q  %  user)\r\n")
    assert fp(tmp_path, code(1))[0]["fingerprint"] == a
    write(tmp_path, "app/db.py", "cur.execute(q % admin)\n")
    assert fp(tmp_path, code(1))[0]["fingerprint"] != a


def test_the_same_line_twice_is_two_findings_stable_under_a_shift(tmp_path):
    write(tmp_path, "app/db.py", "cur.execute(q % user)\nx = 1\ncur.execute(q % user)\n")
    first, second = fp(tmp_path, code(1), code(3))
    assert first["fingerprint"] != second["fingerprint"]
    write(tmp_path, "app/db.py", "\n\ncur.execute(q % user)\nx = 1\ncur.execute(q % user)\n")
    # reported in the other order this time: the occurrence index follows the line, not the list
    second2, first2 = fp(tmp_path, code(5), code(3))
    assert (first2["fingerprint"], second2["fingerprint"]) == (first["fingerprint"], second["fingerprint"])


def test_rule_file_and_dimension_are_part_of_it(tmp_path):
    write(tmp_path, "app/db.py", "cur.execute(q % user)\n")
    write(tmp_path, "app/other.py", "cur.execute(q % user)\n")
    seen = {f["fingerprint"] for f in fp(tmp_path, code(1), code(1, rule="py.other"), code(1, path="app/other.py"),
                                         code(1, dim="judgment"))}
    assert len(seen) == 4


def test_same_advisory_in_two_packages_is_two_findings():
    a, b = fp(".", dep("urllib3", "1.26.4"), dep("requests", "2.0.0"))
    assert a["fingerprint_basis"] == b["fingerprint_basis"] == "package"
    assert a["fingerprint"] != b["fingerprint"]


def test_a_version_bump_is_the_same_finding_and_the_name_is_normalised():
    a, b, c = fp(".", dep("urllib3", "1.26.4"), dep("urllib3", "1.26.5"), dep("URLLIB3", "1.26.4"))
    assert a["fingerprint"] == b["fingerprint"] == c["fingerprint"]
    x, y = fp(".", dep("zope.interface", "5"), dep("Zope_Interface", "5"))
    assert x["fingerprint"] == y["fingerprint"]
    # npm names are not folded: `JSONStream` and `jsonstream` are different packages
    m, n = fp(".", dep("JSONStream", "1", eco="npm", path="package-lock.json"),
              dep("jsonstream", "1", eco="npm", path="package-lock.json"))
    assert m["fingerprint"] != n["fingerprint"]


def test_the_manifest_and_ecosystem_are_part_of_a_package_fingerprint():
    seen = {f["fingerprint"] for f in fp(".", dep("lodash", "1", eco="npm", path="a/package-lock.json"),
                                         dep("lodash", "1", eco="npm", path="b/package-lock.json"),
                                         dep("lodash", "1", eco="pypi", path="a/package-lock.json"))}
    assert len(seen) == 3


def test_a_package_fingerprint_does_not_depend_on_the_machine(tmp_path):
    # pip-audit audits an environment: no manifest, and no venv path in the identity
    assert fp(tmp_path, dep("urllib3", "1"))[0]["fingerprint"] == fp("/", dep("urllib3", "1"))[0]["fingerprint"]


def test_secret_findings_never_hash_the_line(tmp_path):
    write(tmp_path, "config.py", 'KEY = "hunter2"\n')
    f = fp(tmp_path, code(1, rule="generic-api-key", path="config.py", dim="secret"))[0]
    assert f["fingerprint_basis"] == "location"
    write(tmp_path, "config.py", 'KEY = "another"\n')
    assert fp(tmp_path, code(1, rule="generic-api-key", path="config.py", dim="secret"))[0]["fingerprint"] == f["fingerprint"]


def test_paths_that_must_not_be_read_fall_back_to_location(tmp_path):
    root = tmp_path / "repo"
    write(root, "app/db.py", "x\n")
    write(tmp_path, "outside.txt", "secret outside the repo\n")
    os.symlink(str(tmp_path / "outside.txt"), str(root / "link.txt"))
    cases = [code(1, path="../outside.txt"), code(1, path=str(tmp_path / "outside.txt")), code(1, path="link.txt"),
             code(1, path="missing.py"), code(9, path="app/db.py"), code(0, path="app/db.py"),
             code(None, path="app/db.py"), code(True, path="app/db.py"), code(1, path="app")]
    for f in fp(root, *cases):
        assert f["fingerprint_basis"] == "location", f
        assert len(f["fingerprint"]) == fingerprint.FP_CHARS


def test_a_blank_line_and_an_oversized_file_identify_nothing(tmp_path, monkeypatch):
    write(tmp_path, "a.py", "x = 1\n   \n")
    assert fp(tmp_path, code(2, path="a.py"))[0]["fingerprint_basis"] == "location"
    monkeypatch.setattr(fingerprint, "MAX_FILE_BYTES", 4)
    assert fp(tmp_path, code(1, path="a.py"))[0]["fingerprint_basis"] == "location"


def test_lines_are_counted_as_scanners_count_them(tmp_path):
    # a form feed is not a line break: str.splitlines would shift every number after it
    write(tmp_path, "a.py", "a = 1\x0cb = 2\ntarget()\n")
    write(tmp_path, "b.py", "target()\n")
    f = fp(tmp_path, code(2, path="a.py"), code(1, path="a.py"))
    assert f[0]["fingerprint_basis"] == "line-content" and f[0]["fingerprint"] != f[1]["fingerprint"]


def test_every_finding_gets_one_and_the_result_is_deterministic(tmp_path):
    write(tmp_path, "app/db.py", "cur.execute(q % user)\n")
    rows = [code(1), dep("urllib3", "1"), {"id": "x", "dimension": "iac", "rule_id": "CKV_1", "file": None, "line": None}]
    one, two = fp(tmp_path, *rows), fp(tmp_path, *reversed(rows))
    assert all(f.get("fingerprint") and f.get("fingerprint_basis") for f in one)
    assert sorted(f["fingerprint"] for f in one) == sorted(f["fingerprint"] for f in two)
    assert len({f["fingerprint"] for f in one}) == 3


# --- slice 2: one advisory under several names; dependency rows that arrive as SARIF --------------

import json  # noqa: E402

import evidence  # noqa: E402
import native  # noqa: E402

UVLOCK = os.path.join(os.path.dirname(__file__), "..", "fixtures", "native", "uvlock")


def recorded(name, tool, dimension):
    rows = evidence.collect(os.path.join(UVLOCK, name), tool, dimension, [])
    unique = {r["id"]: r for r in reversed(rows)}          # as evidence.main drops a tool's repeats
    return list(unique.values())


def test_canonical_advisory_prefers_cve_then_ghsa_and_uses_only_the_rows_own_names():
    c = fingerprint.canonical_advisory
    assert c("PYSEC-2021-108", ["GHSA-q2q7-5pp4-w6pg", "CVE-2021-33503"]) == "CVE-2021-33503"
    assert c("CVE-2021-33503", []) == c("CVE-2021-33503", None) == "CVE-2021-33503"
    assert c("PYSEC-2021-108", ["GHSA-q2q7-5pp4-w6pg"]) == "GHSA-q2q7-5pp4-w6pg"
    assert c("PYSEC-2021-108", []) == "PYSEC-2021-108"
    assert c("GHSA-b", ["CVE-2024-2", "CVE-2024-1"]) == "CVE-2024-1"      # two CVEs: the first, always
    assert c("exec-base64", None) == "exec-base64"                         # a guarddog rule is its own name
    assert c("X", ["", None, 7, " "]) == "X"


def test_manifest_ecosystem_reads_the_file_name_and_says_nothing_when_it_cannot():
    e = fingerprint.manifest_ecosystem
    assert [e(p) for p in ("requirements.txt", "svc/requirements-dev.txt", "uv.lock", "a/poetry.lock")] == ["pypi"] * 4
    assert [e(p) for p in ("package-lock.json", "web/yarn.lock", "pnpm-lock.yaml")] == ["npm"] * 3
    assert e("go.sum") == "go" and e("Cargo.lock") == "crates.io" and e("Gemfile.lock") == "rubygems"
    assert e("notrequirements.txt.bak") == "" and e("Dockerfile") == "" and e(None) == "" and e("my-uv.lock") == ""


def test_recorded_osv_and_trivy_rows_carry_the_package_and_osv_its_aliases():
    osv = recorded("osv-v2.4.0-source.sarif", "osv-scanner", "osv")
    trivy = recorded("trivy-0.58.0-requirements.sarif", "trivy", "container")
    assert len(osv) == 22 and len(trivy) == 8                 # 11 advisories x 2 manifests; 8 HIGH with a fix
    for r in osv + trivy:
        assert r["package"] == {"ecosystem": "pypi", "name": "urllib3", "version": "1.26.4"}, r
    o = next(r for r in osv if r["rule_id"] == "CVE-2021-33503" and r["file"] == "requirements.txt")
    assert o["aliases"] == ["GHSA-q2q7-5pp4-w6pg", "PYSEC-2021-108"]
    t = next(r for r in trivy if r["rule_id"] == "CVE-2021-33503")
    assert t["fixed_in"] == ["1.26.5"] and "aliases" not in t
    assert next(r for r in trivy if r["rule_id"] == "CVE-2023-43804")["fixed_in"] == ["2.0.6", "1.26.17"]


def test_two_tools_one_advisory_one_manifest_is_one_fingerprint():
    osv = recorded("osv-v2.4.0-source.sarif", "osv-scanner", "osv")
    trivy = recorded("trivy-0.58.0-requirements.sarif", "trivy", "container")
    rows = fp(".", *osv, *trivy)
    by = {(r["tool"], r["rule_id"], r["file"]): r for r in rows}
    assert all(r["fingerprint_basis"] == "package" for r in rows)
    same = by[("osv-scanner", "CVE-2021-33503", "requirements.txt")]["fingerprint"]
    assert by[("trivy", "CVE-2021-33503", "requirements.txt")]["fingerprint"] == same
    # the other manifest is another finding: fixing one lock file does not fix the other
    assert by[("osv-scanner", "CVE-2021-33503", "uv.lock")]["fingerprint"] != same
    # every advisory trivy reports is one osv-scanner reports for the same file, under the same name
    shared = {r["fingerprint"] for r in rows if r["tool"] == "trivy"} & {r["fingerprint"] for r in rows if r["tool"] == "osv-scanner"}
    assert len(shared) == 8


def test_pip_audit_names_it_pysec_and_still_meets_the_cve():
    doc = json.load(open(os.path.join(UVLOCK, "pip-audit-2.10.1-exported.json"), encoding="utf-8"))
    pa = next(r for r in native.parse_pip_audit(doc, []) if r["rule_id"] == "PYSEC-2021-108")
    a, b = fp(".", pa, dict(pa, rule_id="CVE-2021-33503", aliases=[]))
    assert a["fingerprint"] == b["fingerprint"]
    # ...but its manifest is the environment, so it is not the requirements.txt finding
    t = next(r for r in recorded("trivy-0.58.0-requirements.sarif", "trivy", "container") if r["rule_id"] == "CVE-2021-33503")
    assert fp(".", t)[0]["fingerprint"] != a["fingerprint"]


def test_a_message_that_is_not_the_recorded_shape_adds_no_package():
    rule = {"name": "LanguageSpecificPackageVulnerability", "deprecatedIds": "CVE-1"}
    sp = evidence.sarif_package
    assert sp("trivy", {"message": {"text": "something else"}}, rule, "requirements.txt") == {}
    assert sp("trivy", {"message": {"text": "Package: x\nInstalled Version: 1"}}, {"name": "Secret"}, "a") == {}
    assert sp("osv-scanner", {"message": {"text": "Package urllib3 is fine"}}, rule, "uv.lock") == {}
    assert sp("osv-scanner", {"message": {"text": 7}}, rule, "uv.lock") == {}
    assert sp("semgrep", {"message": {"text": "Package 'a@1' is vulnerable to 'X'"}}, rule, "uv.lock") == {}
    scoped = sp("osv-scanner", {"ruleId": "GHSA-x", "message": {"text": "Package '@scope/pkg@2.0.0' is vulnerable to 'GHSA-x'."}}, {}, "web/package-lock.json")
    assert scoped == {"package": {"ecosystem": "npm", "name": "@scope/pkg", "version": "2.0.0"}}
    long = sp("trivy", {"message": {"text": "Package: " + "a" * 500 + "‮\nInstalled Version: 1"}}, rule, "x.lock")
    assert len(long["package"]["name"]) == 200 and long["package"]["ecosystem"] == ""
