"""Tests for lib/native.py — adapters for tools that write native JSON instead of SARIF (F16b)."""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "lib"))

import native  # noqa: E402

RECORDED = os.path.join(os.path.dirname(__file__), "..", "fixtures", "native", "uvlock", "pip-audit-2.10.1-exported.json")


def _dep(name="urllib3", version="1.26.4", vulns=None, **extra):
    d = {"name": name, "version": version, "vulns": vulns if vulns is not None else []}
    d.update(extra)
    return d


class TestParsePipAudit:
    def test_recorded_output_gives_one_row_per_advisory(self):
        rows = native.parse_pip_audit(json.load(open(RECORDED)), [])
        assert rows and len(rows) == len({r["rule_id"] for r in rows})
        r = [x for x in rows if x["rule_id"] == "PYSEC-2021-108"][0]
        assert r["severity"] == "unknown" and r["severity_source"] == "pip-audit:none" and r["cvss"] is None
        assert r["package"] == {"ecosystem": "pypi", "name": "urllib3", "version": "1.26.4"}
        assert set(r["aliases"]) == {"CVE-2021-33503", "GHSA-q2q7-5pp4-w6pg"} and r["fixed_in"] == ["1.26.5"]
        assert r["dimension"] == "py-deps" and r["file"] is None and r["line"] is None

    def test_a_repeated_advisory_is_one_row(self):
        v = {"id": "PYSEC-1", "fix_versions": ["2"], "aliases": []}
        assert len(native.parse_pip_audit({"dependencies": [_dep(vulns=[v, v])]}, [])) == 1

    def test_same_advisory_in_two_packages_is_two_rows_with_two_ids(self):
        v = {"id": "GHSA-x", "fix_versions": [], "aliases": []}
        rows = native.parse_pip_audit({"dependencies": [_dep("a", vulns=[v]), _dep("b", vulns=[v])]}, [])
        assert len(rows) == 2 and rows[0]["id"] != rows[1]["id"]

    def test_the_id_does_not_change_with_the_version(self):
        v = {"id": "PYSEC-1", "fix_versions": [], "aliases": []}
        a = native.parse_pip_audit({"dependencies": [_dep(version="1.0", vulns=[v])]}, [])[0]["id"]
        b = native.parse_pip_audit({"dependencies": [_dep(version="1.1", vulns=[v])]}, [])[0]["id"]
        assert a == b

    def test_a_skipped_package_is_said_not_dropped_silently(self):
        w = []
        rows = native.parse_pip_audit({"dependencies": [_dep("private-pkg", skip_reason="not on PyPI")]}, w)
        assert rows == [] and any("private-pkg not audited" in x for x in w)

    def test_no_fix_is_said(self):
        v = {"id": "PYSEC-1", "fix_versions": [], "aliases": []}
        assert native.parse_pip_audit({"dependencies": [_dep(vulns=[v])]}, [])[0]["message"].endswith("no fixed version")

    @pytest.mark.parametrize("doc", [None, [], {"x": 1}, {"dependencies": "nope"}])
    def test_not_pip_audit_json_gives_no_rows_and_a_warning(self, doc):
        w = []
        assert native.parse_pip_audit(doc, w) == [] and w


class TestSummary:
    def test_recorded_output_summarises_and_notes_repeats(self, capsys):
        assert native.summary("pip-audit", RECORDED) == 0
        out = capsys.readouterr().out
        assert "urllib3 1.26.4: PYSEC-2021-108, fixed in 1.26.5" in out and "repeats advisories" in out

    def test_unreadable_file_is_2(self, tmp_path):
        p = tmp_path / "x.json"; p.write_text("{not json")
        assert native.summary("pip-audit", str(p)) == 2

    def test_json_that_is_not_pip_audit_is_2(self, tmp_path):
        p = tmp_path / "x.json"; p.write_text('{"not": "pip-audit"}')
        assert native.summary("pip-audit", str(p)) == 2
