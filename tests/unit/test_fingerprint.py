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
