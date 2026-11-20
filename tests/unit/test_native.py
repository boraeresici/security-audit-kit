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


CHECKOV = os.path.join(os.path.dirname(__file__), "..", "fixtures", "native", "checkov", "checkov-3.3.1.json")


class TestParseCheckov:
    def test_recorded_output_gives_failed_and_skipped_checks(self):
        rows = native.parse_checkov(json.load(open(CHECKOV)), [])
        assert len(rows) == 10 and sum(r["decision"] == "suppressed" for r in rows) == 1
        r = [x for x in rows if x["rule_id"] == "CKV_AWS_24"][0]
        assert r["file"] == "infra/main.tf" and r["line"] == 6 and r["dimension"] == "iac"
        assert r["severity"] == "unknown" and r["severity_source"] == "checkov:none" and r["decision"] is None
        assert r["resource"] == "aws_security_group.web" and r["message"].startswith("aws_security_group.web: ")

    def test_a_checkov_skip_is_suppressed_with_its_reason(self):
        s = [x for x in native.parse_checkov(json.load(open(CHECKOV)), []) if x["decision"]][0]
        assert s["rule_id"] == "CKV_AWS_18"
        assert s["evidence"]["note"] == "suppressed in source (#checkov:skip): access logging is the logs bucket itself"

    def test_a_list_of_frameworks_is_read(self):
        doc = json.load(open(CHECKOV))
        assert len(native.parse_checkov([doc, doc], [])) == 20

    def test_a_severity_checkov_gives_is_kept(self):
        doc = {"results": {"failed_checks": [{"check_id": "CKV_X", "severity": "HIGH", "repo_file_path": "/a.tf",
                                              "file_line_range": [3, 4], "resource": "r"}]}}
        r = native.parse_checkov(doc, [])[0]
        assert r["severity"] == "high" and r["severity_source"] == "checkov:high"

    def test_parsing_errors_are_said(self):
        w = []
        native.parse_checkov({"results": {"failed_checks": [], "parsing_errors": ["/bad.tf"]}}, w)
        assert any("could not parse /bad.tf" in x for x in w)

    @pytest.mark.parametrize("doc", [None, {}, {"results": []}, [{"x": 1}], []])
    def test_not_checkov_json_gives_no_rows_and_a_warning(self, doc):
        w = []
        assert native.parse_checkov(doc, w) == [] and w
