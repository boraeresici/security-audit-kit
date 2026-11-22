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


GD = os.path.join(os.path.dirname(__file__), "..", "fixtures", "native", "guarddog")


def _gd_record(name="verify-pypi-3.0.2.json", eco="pypi", manifest="requirements.txt", requested=None):
    verify = json.load(open(os.path.join(GD, name)))
    if requested is None:
        requested = native.requested_packages(eco, os.path.join(GD, f"{'requirements.txt' if eco == 'pypi' else 'package.json'}.fixture"))
    return {"files": [{"ecosystem": eco, "manifest": manifest, "requested": requested, "verify": verify}]}


class TestRequestedPackages:
    def test_pypi_names_are_normalised_and_options_skipped(self, tmp_path):
        p = tmp_path / "r.txt"
        p.write_text("Foo_Bar==1.0  # pinned\n-r other.txt\n--hash=sha256:x\n\nzope.interface>=5\n")
        assert native.requested_packages("pypi", str(p)) == ["foo-bar", "zope-interface"]

    def test_npm_reads_dependencies_and_devdependencies(self):
        assert native.requested_packages("npm", os.path.join(GD, "package.json.fixture")) == ["is-number", "ms"]

    def test_unreadable_manifest_is_empty(self, tmp_path):
        assert native.requested_packages("npm", str(tmp_path / "missing.json")) == []


class TestParseGuarddog:
    def test_recorded_pypi_run(self):
        w = []
        rows = native.parse_guarddog(_gd_record(), w)
        assert rows and all(r["package"]["name"] == "setuptools" for r in rows)       # requests: capabilities only
        assert not any(r["rule_id"].startswith("capability-") for r in rows)
        sev = {r["rule_id"]: r["severity"] for r in rows}
        assert sev["threat-filesystem-read"] == "high" and sev["threat-runtime-obfuscation-unicode"] == "medium"
        assert all(r["severity_source"] == f"guarddog:{r['severity']}" for r in rows)
        assert any("f16-no-such-package-xyz" in x and "not checked" in x for x in w)

    def test_recorded_npm_run_is_clean(self):
        w = []
        assert native.parse_guarddog(_gd_record("verify-npm-3.0.2.json", "npm", "package.json"), w) == [] and w == []

    def test_one_failing_rule_keeps_the_others(self):
        doc = {"files": [{"ecosystem": "pypi", "manifest": "r.txt", "requested": ["x"], "verify": [
            {"dependency": "x", "version": "1", "result": {"errors": {"r1": "timed out"},
             "results": {"threat-a": [{"location": "x.py:1"}], "capability-b": [{"location": "y"}]}, "risks": []}}]}]}
        w = []
        rows = native.parse_guarddog(doc, w)
        assert [r["rule_id"] for r in rows] == ["threat-a"] and rows[0]["severity"] == "unknown"
        assert any("some rules did not run" in x for x in w)

    def test_no_results_is_not_scanned(self):
        doc = {"files": [{"ecosystem": "pypi", "manifest": "r.txt", "requested": ["x"],
                          "verify": [{"dependency": "x", "version": "1", "result": {"errors": {"dl": "404"}}}]}]}
        w = []
        assert native.parse_guarddog(doc, w) == [] and any("x 1 not scanned" in x for x in w)

    def test_same_rule_in_two_manifests_is_two_rows(self):
        a = native.parse_guarddog(_gd_record(manifest="a/requirements.txt"), [])
        b = native.parse_guarddog(_gd_record(manifest="b/requirements.txt"), [])
        assert {r["id"] for r in a}.isdisjoint({r["id"] for r in b})

    @pytest.mark.parametrize("doc", [None, {}, {"files": "x"}, []])
    def test_not_the_kits_record_gives_no_rows_and_a_warning(self, doc):
        w = []
        assert native.parse_guarddog(doc, w) == [] and w


class TestGuarddogAdd:
    def test_appends_and_reports(self, tmp_path, capsys):
        rec = tmp_path / "rec.json"
        man = os.path.join(GD, "requirements.txt.fixture")
        for _ in range(2):
            assert native.guarddog_add("pypi", man, os.path.join(GD, "verify-pypi-3.0.2.json"), str(rec)) == 0
        assert len(json.load(open(rec))["files"]) == 2
        out = capsys.readouterr().out
        assert "2 of 3 package(s) checked" in out and "not checked" in out

    def test_unreadable_output_is_2(self, tmp_path):
        bad = tmp_path / "v.json"; bad.write_text("{not json")
        assert native.guarddog_add("pypi", "r.txt", str(bad), str(tmp_path / "rec.json")) == 2


def _gd_rule(rule, name="pkg"):
    return {"files": [{"ecosystem": "pypi", "manifest": "r.txt", "requested": [name], "verify": [
        {"dependency": name, "version": "1", "result": {"errors": {}, "results": {rule: [{"location": "x.py:1"}]}, "risks": []}}]}]}


class TestGuarddogGate:
    def _rec(self, tmp_path, doc):
        p = tmp_path / "rec.json"; p.write_text(json.dumps(doc)); return str(p)

    def test_a_block_list_rule_blocks(self, tmp_path, capsys):
        assert native.guarddog_gate(self._rec(tmp_path, _gd_rule("typosquatting"))) == 1
        assert "BLOCK — pkg: typosquatting" in capsys.readouterr().out

    def test_rules_off_the_block_list_are_reported_not_blocking(self, tmp_path):
        assert native.guarddog_gate(self._rec(tmp_path, _gd_record())) == 4      # setuptools, recorded

    def test_capabilities_only_pass(self, tmp_path):
        assert native.guarddog_gate(self._rec(tmp_path, _gd_rule("capability-process-spawn"))) == 0

    def test_block_extra_and_report_extra_as_in_pkgcheck(self, tmp_path):
        rec = self._rec(tmp_path, _gd_rule("threat-filesystem-read"))
        assert native.guarddog_gate(rec) == 4
        assert native.guarddog_gate(rec, "threat-filesystem-read") == 1
        assert native.guarddog_gate(self._rec(tmp_path, _gd_rule("typosquatting")), "", "typosquatting") == 4

    def test_unreadable_record_is_2(self, tmp_path):
        assert native.guarddog_gate(str(tmp_path / "missing.json")) == 2


NPM = os.path.join(os.path.dirname(__file__), "..", "fixtures", "native", "npm-audit", "npm-audit-11.9.0.json")


class TestParseNpmAudit:
    def _rec(self, d="web"):
        return {"dirs": [{"dir": d, "audit": json.load(open(NPM))}]}

    def test_recorded_report_gives_one_row_per_package_and_advisory(self):
        rows = native.parse_npm_audit(self._rec(), [])
        assert len(rows) == 5 and len({r["id"] for r in rows}) == 5
        r = [x for x in rows if x["rule_id"] == "GHSA-xvch-5gv4-984h"][0]
        assert r["package"]["name"] == "minimist" and r["severity"] == "critical" and r["cvss"] == 9.8
        assert r["file"] == "web/package-lock.json" and r["direct"] is True and r["fixed_in"] == ["1.2.8"]

    def test_moderate_is_medium_and_the_source_is_kept(self):
        r = [x for x in native.parse_npm_audit(self._rec(), []) if x["rule_id"] == "GHSA-29mw-wpgm-hmr9"][0]
        assert r["severity"] == "medium" and r["severity_source"] == "npm:moderate"

    def test_root_project_lockfile_path(self):
        assert {r["file"] for r in native.parse_npm_audit(self._rec("."), [])} == {"package-lock.json"}

    def test_a_package_listed_only_through_another_is_not_a_row(self):
        doc = {"dirs": [{"dir": ".", "audit": {"vulnerabilities": {"wrapper": {"severity": "high", "via": ["lodash"]}}}}]}
        assert native.parse_npm_audit(doc, []) == []

    def test_an_advisory_without_a_ghsa_url_keeps_npm_source_id(self):
        doc = {"dirs": [{"dir": ".", "audit": {"vulnerabilities": {"x": {"via": [
            {"source": 42, "title": "t", "severity": "low", "url": "https://example.test/x"}]}}}}]}
        assert native.parse_npm_audit(doc, [])[0]["rule_id"] == "npm-42"

    @pytest.mark.parametrize("doc", [None, {}, {"dirs": "x"}])
    def test_not_the_kits_record_gives_no_rows_and_a_warning(self, doc):
        w = []
        assert native.parse_npm_audit(doc, w) == [] and w


class TestNpmAdd:
    def test_appends_and_reports(self, tmp_path, capsys):
        rec = tmp_path / "rec.json"
        assert native.npm_add("web", NPM, str(rec)) == 0
        assert json.load(open(rec))["dirs"][0]["dir"] == "web"
        assert "web: 5 advisories in 2 package(s)" in capsys.readouterr().out

    def test_an_npm_error_object_is_2_and_nothing_is_recorded(self, tmp_path, capsys):
        err = tmp_path / "e.json"; err.write_text('{"error": {"code": "ENOTFOUND", "summary": "registry unreachable"}}')
        rec = tmp_path / "rec.json"
        assert native.npm_add(".", str(err), str(rec)) == 2 and not rec.exists()
        assert "ENOTFOUND" in capsys.readouterr().out
