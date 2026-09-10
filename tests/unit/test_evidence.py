"""Comprehensive unit tests for lib/evidence.py."""
from __future__ import annotations

import json
import os
import sys
import textwrap

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "lib"))

import evidence  # noqa: E402


# ---------------------------------------------------------------------------
# band()
# ---------------------------------------------------------------------------
class TestBand:
    def test_critical_high_end(self):
        assert evidence.band(9.5) == "critical"

    def test_critical_boundary(self):
        assert evidence.band(9.0) == "critical"

    def test_high_boundary(self):
        assert evidence.band(7.0) == "high"

    def test_medium_boundary(self):
        assert evidence.band(4.0) == "medium"

    def test_low(self):
        assert evidence.band(0.1) == "low"

    def test_info_at_zero(self):
        assert evidence.band(0.0) == "info"

    def test_just_below_critical(self):
        assert evidence.band(8.9) == "high"

    def test_just_below_high(self):
        assert evidence.band(6.9) == "medium"

    def test_just_below_medium(self):
        assert evidence.band(3.9) == "low"


# ---------------------------------------------------------------------------
# classify()
# ---------------------------------------------------------------------------
class TestClassify:
    def test_security_severity_cvss_tool(self):
        """trivy IS in CVSS_TOOLS, so cvss should be passed through."""
        rule = {"properties": {"security-severity": "8.8"}}
        sev, src, cvss = evidence.classify("trivy", {}, rule, [], "test.sarif:R1")
        assert sev == "high"
        assert src == "trivy:security-severity=8.8"
        assert cvss == 8.8

    def test_security_severity_non_cvss_tool(self):
        """semgrep is NOT in CVSS_TOOLS, so cvss should be None."""
        rule = {"properties": {"security-severity": "8.8"}}
        sev, src, cvss = evidence.classify("semgrep", {}, rule, [], "test.sarif:R1")
        assert sev == "high"
        assert src == "semgrep:security-severity=8.8"
        assert cvss is None

    def test_level_error(self):
        result = {"level": "error"}
        sev, src, cvss = evidence.classify("semgrep", result, {}, [], "test.sarif:R1")
        assert sev == "high"
        assert src == "semgrep:level=error"
        assert cvss is None

    def test_level_warning(self):
        result = {"level": "warning"}
        sev, src, cvss = evidence.classify("semgrep", result, {}, [], "test.sarif:R1")
        assert sev == "medium"
        assert src == "semgrep:level=warning"
        assert cvss is None

    def test_level_note(self):
        result = {"level": "note"}
        sev, src, cvss = evidence.classify("semgrep", result, {}, [], "test.sarif:R1")
        assert sev == "low"

    def test_level_none_value(self):
        result = {"level": "none"}
        sev, src, cvss = evidence.classify("semgrep", result, {}, [], "test.sarif:R1")
        assert sev == "info"

    def test_tool_default_gitleaks(self):
        """No severity signal, gitleaks has a TOOL_DEFAULT of 'high'."""
        sev, src, cvss = evidence.classify("gitleaks", {}, {}, [], "test.sarif:R1")
        assert sev == "high"
        assert src == "gitleaks:none"
        assert cvss is None

    def test_no_signal_unknown_tool(self):
        """Unknown tool with no default -> info + warning."""
        warnings = []
        sev, src, cvss = evidence.classify("unknown-tool", {}, {}, warnings, "test.sarif:R1")
        assert sev == "info"
        assert cvss is None
        assert len(warnings) == 1
        assert "no severity signal" in warnings[0]

    def test_unmapped_level(self):
        """A level value not in LEVEL_TO_SEVERITY -> info + warning."""
        warnings = []
        result = {"level": "catastrophic"}
        sev, src, cvss = evidence.classify("tool", result, {}, warnings, "test.sarif:R1")
        assert sev == "info"
        assert len(warnings) == 1
        assert "unmapped SARIF level" in warnings[0]

    def test_rule_default_configuration_level(self):
        """Level from rule's defaultConfiguration when result has no level."""
        rule = {"defaultConfiguration": {"level": "warning"}}
        sev, src, cvss = evidence.classify("semgrep", {}, rule, [], "test.sarif:R1")
        assert sev == "medium"
        assert src == "semgrep:level=warning"

    def test_security_severity_critical(self):
        rule = {"properties": {"security-severity": "9.5"}}
        sev, src, cvss = evidence.classify("trivy", {}, rule, [], "test.sarif:R1")
        assert sev == "critical"
        assert cvss == 9.5

    def test_security_severity_takes_priority_over_level(self):
        """When both security-severity and level exist, security-severity wins."""
        rule = {"properties": {"security-severity": "9.5"}}
        result = {"level": "note"}
        sev, src, cvss = evidence.classify("trivy", result, rule, [], "test.sarif:R1")
        assert sev == "critical"


# ---------------------------------------------------------------------------
# location_of()
# ---------------------------------------------------------------------------
class TestLocationOf:
    def test_normal_location(self):
        result = {
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/app.py"},
                    "region": {"startLine": 42},
                }
            }]
        }
        path, line = evidence.location_of(result)
        assert path == "src/app.py"
        assert line == 42

    def test_container_mount_strip(self):
        result = {
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "file:///repo/src/app.py"},
                    "region": {"startLine": 10},
                }
            }]
        }
        path, line = evidence.location_of(result)
        assert path == "src/app.py"
        assert line == 10

    def test_no_locations(self):
        path, line = evidence.location_of({})
        assert path is None
        assert line is None

    def test_empty_locations_list(self):
        path, line = evidence.location_of({"locations": []})
        assert path is None
        assert line is None

    def test_no_region(self):
        result = {
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/app.py"},
                }
            }]
        }
        path, line = evidence.location_of(result)
        assert path == "src/app.py"
        assert line is None

    def test_no_uri(self):
        result = {
            "locations": [{
                "physicalLocation": {
                    "region": {"startLine": 5},
                }
            }]
        }
        path, line = evidence.location_of(result)
        assert path is None
        assert line is None

    def test_container_mount_without_file_scheme(self):
        """A bare /repo/ prefix (no file://) should also be stripped."""
        result = {
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "/repo/src/main.py"},
                    "region": {"startLine": 1},
                }
            }]
        }
        path, line = evidence.location_of(result)
        assert path == "src/main.py"


# ---------------------------------------------------------------------------
# finding_id()
# ---------------------------------------------------------------------------
class TestFindingId:
    def test_deterministic(self):
        a = evidence.finding_id("sast", "R1", "app.py", 10)
        b = evidence.finding_id("sast", "R1", "app.py", 10)
        assert a == b

    def test_different_line_different_id(self):
        a = evidence.finding_id("sast", "R1", "app.py", 10)
        b = evidence.finding_id("sast", "R1", "app.py", 20)
        assert a != b

    def test_none_line(self):
        fid = evidence.finding_id("sast", "R1", "app.py", None)
        assert isinstance(fid, str)
        assert len(fid) == 12

    def test_is_12_hex_chars(self):
        fid = evidence.finding_id("secret", "rule-1", "f.py", 1)
        assert len(fid) == 12
        int(fid, 16)  # should not raise

    def test_different_dimension(self):
        a = evidence.finding_id("sast", "R1", "app.py", 10)
        b = evidence.finding_id("secret", "R1", "app.py", 10)
        assert a != b


# ---------------------------------------------------------------------------
# message_of()
# ---------------------------------------------------------------------------
class TestMessageOf:
    def test_whitespace_normalization(self):
        result = {"message": {"text": "  foo   bar  "}}
        assert evidence.message_of(result) == "foo bar"

    def test_empty(self):
        assert evidence.message_of({}) == ""

    def test_no_text_key(self):
        assert evidence.message_of({"message": {}}) == ""

    def test_multiline_collapse(self):
        result = {"message": {"text": "line1\n  line2\n\nline3"}}
        assert evidence.message_of(result) == "line1 line2 line3"

    def test_none_message(self):
        assert evidence.message_of({"message": None}) == ""


# ---------------------------------------------------------------------------
# parse_location()
# ---------------------------------------------------------------------------
class TestParseLocation:
    def test_normal_with_line(self):
        path, line = evidence.parse_location("path/to/x.py:88")
        assert path == "path/to/x.py"
        assert line == 88

    def test_no_line(self):
        path, line = evidence.parse_location("path/to/x.py")
        assert path == "path/to/x.py"
        assert line is None

    def test_empty(self):
        path, line = evidence.parse_location("")
        assert path is None
        assert line is None

    def test_dash(self):
        path, line = evidence.parse_location("-")
        assert path is None
        assert line is None

    def test_na(self):
        path, line = evidence.parse_location("n/a")
        assert path is None
        assert line is None

    def test_backtick_wrapped(self):
        path, line = evidence.parse_location("`src/main.py:5`")
        assert path == "src/main.py"
        assert line == 5

    def test_em_dash(self):
        path, line = evidence.parse_location("—")
        assert path is None
        assert line is None


# ---------------------------------------------------------------------------
# is_separator()
# ---------------------------------------------------------------------------
class TestIsSeparator:
    def test_standard_separator(self):
        assert evidence.is_separator("|---|---|") is True

    def test_with_colons(self):
        assert evidence.is_separator("|:---|:---:|---:|") is True

    def test_not_separator_content(self):
        assert evidence.is_separator("| foo | bar |") is False

    def test_not_separator_no_pipe(self):
        assert evidence.is_separator("---") is False

    def test_wide_separator(self):
        assert evidence.is_separator("| -------- | -------- |") is True


# ---------------------------------------------------------------------------
# split_row()
# ---------------------------------------------------------------------------
class TestSplitRow:
    def test_standard_row(self):
        assert evidence.split_row("| a | b | c |") == ["a", "b", "c"]

    def test_single_cell(self):
        assert evidence.split_row("| only |") == ["only"]

    def test_strips_whitespace(self):
        assert evidence.split_row("|  x  |  y  |") == ["x", "y"]

    def test_empty_cells(self):
        assert evidence.split_row("| | |") == ["", ""]


# ---------------------------------------------------------------------------
# column_role()
# ---------------------------------------------------------------------------
class TestColumnRole:
    def test_sink_location(self):
        assert evidence.column_role("Sink (file:line)") == "loc"

    def test_tool(self):
        assert evidence.column_role("Tool") == "tool"

    def test_severity(self):
        assert evidence.column_role("Sev") == "sev"

    def test_severity_full(self):
        assert evidence.column_role("Severity") == "sev"

    def test_decision(self):
        assert evidence.column_role("Decision") == "decision"

    def test_verdict(self):
        assert evidence.column_role("Verdict") == "decision"

    def test_confidence(self):
        assert evidence.column_role("Confidence") == "conf"

    def test_action(self):
        assert evidence.column_role("Action") == "action"

    def test_why(self):
        assert evidence.column_role("Why") == "why"

    def test_reason(self):
        assert evidence.column_role("Reason") == "why"

    def test_class(self):
        assert evidence.column_role("Class") == "cls"

    def test_owasp(self):
        assert evidence.column_role("OWASP") == "cls"

    def test_rule(self):
        assert evidence.column_role("Rule") == "cls"

    def test_id(self):
        assert evidence.column_role("ID") == "cls"

    def test_source(self):
        assert evidence.column_role("Source") == "source"

    def test_where(self):
        assert evidence.column_role("Where") == "loc"

    def test_unknown(self):
        assert evidence.column_role("Something Else") is None

    def test_fix(self):
        assert evidence.column_role("Fix") == "action"


# ---------------------------------------------------------------------------
# parse_findings_md()
# ---------------------------------------------------------------------------
class TestParseFindingsMd:
    def test_normal_triage_table(self, tmp_path):
        md = tmp_path / "findings.md"
        md.write_text(textwrap.dedent("""\
            # sec-triage findings

            | Sink (file:line) | Tool | Sev | Decision | Why |
            |---|---|---|---|---|
            | src/app.py:42 | semgrep | high | real | SQL injection found |
            | lib/util.py:10 | trivy | medium | fp | Not exploitable |
        """))
        warnings = []
        results = evidence.parse_findings_md(str(md), warnings)
        assert len(results) == 2
        assert results[0]["file"] == "src/app.py"
        assert results[0]["line"] == 42
        assert results[0]["severity"] == "high"
        assert results[0]["decision"] == "real"
        assert results[1]["file"] == "lib/util.py"
        assert results[1]["decision"] == "fp"

    def test_suppressed_section(self, tmp_path):
        md = tmp_path / "findings.md"
        md.write_text(textwrap.dedent("""\
            # sec-triage findings

            ## Suppressed findings

            | Sink (file:line) | Tool | Sev | Decision |
            |---|---|---|---|
            | src/old.py:5 | semgrep | low | fp |
        """))
        warnings = []
        results = evidence.parse_findings_md(str(md), warnings)
        assert len(results) == 1
        assert results[0]["decision"] == "suppressed"

    def test_kit_issues_section_skipped(self, tmp_path):
        md = tmp_path / "findings.md"
        md.write_text(textwrap.dedent("""\
            # sec-triage findings

            | Sink (file:line) | Tool | Sev | Decision |
            |---|---|---|---|
            | src/app.py:1 | semgrep | high | real |

            ## Kit issues

            | Sink (file:line) | Tool | Sev | Decision |
            |---|---|---|---|
            | kit/bug.py:1 | internal | high | real |
        """))
        warnings = []
        results = evidence.parse_findings_md(str(md), warnings)
        assert len(results) == 1
        assert results[0]["file"] == "src/app.py"

    def test_missing_file_returns_empty(self, tmp_path):
        warnings = []
        results = evidence.parse_findings_md(str(tmp_path / "nonexistent.md"), warnings)
        assert results == []

    def test_unmapped_severity_warning(self, tmp_path):
        md = tmp_path / "findings.md"
        md.write_text(textwrap.dedent("""\
            # sec-triage

            | Sink (file:line) | Sev | Decision |
            |---|---|---|
            | src/x.py:1 | apocalyptic | real |
        """))
        warnings = []
        results = evidence.parse_findings_md(str(md), warnings)
        assert len(results) == 1
        assert results[0]["severity"] == "info"
        assert any("unmapped severity" in w for w in warnings)

    def test_no_decision_becomes_none(self, tmp_path):
        md = tmp_path / "findings.md"
        md.write_text(textwrap.dedent("""\
            # sec-triage

            | Sink (file:line) | Sev |
            |---|---|
            | src/x.py:1 | high |
        """))
        warnings = []
        results = evidence.parse_findings_md(str(md), warnings)
        assert len(results) == 1
        assert results[0]["decision"] is None

    def test_uncertain_decision_when_unrecognized(self, tmp_path):
        md = tmp_path / "findings.md"
        md.write_text(textwrap.dedent("""\
            # sec-triage

            | Sink (file:line) | Sev | Decision |
            |---|---|---|
            | src/x.py:1 | high | maybe |
        """))
        warnings = []
        results = evidence.parse_findings_md(str(md), warnings)
        assert len(results) == 1
        assert results[0]["decision"] == "uncertain"


# ---------------------------------------------------------------------------
# merge_judgment()
# ---------------------------------------------------------------------------
class TestMergeJudgment:
    def _scanner_finding(self, file="src/app.py", line=42, tool="semgrep", dimension="sast"):
        return {
            "id": evidence.finding_id(dimension, "R1", file, line),
            "dimension": dimension,
            "tool": tool,
            "rule_id": "R1",
            "file": file,
            "line": line,
            "message": "scanner found it",
            "severity": "high",
            "severity_source": "semgrep:level=error",
            "cvss": None,
            "decision": None,
            "confidence": None,
            "evidence": None,
        }

    def test_matching_finding_gets_decision(self):
        scanner = [self._scanner_finding()]
        judged = [{
            "origin": "sec-triage",
            "tool": "semgrep",
            "rule_id": "SAK-triage-semgrep",
            "file": "src/app.py",
            "line": 42,
            "message": "confirmed",
            "severity": "high",
            "severity_source": "sec-triage:high",
            "decision": "real",
            "confidence": 0.9,
            "evidence": {"sink": "src/app.py:42", "source": None, "note": "confirmed"},
        }]
        warnings = []
        result = evidence.merge_judgment(scanner, judged, warnings)
        assert len(result) == 1
        assert result[0]["decision"] == "real"
        assert result[0]["confidence"] == 0.9

    def test_non_matching_becomes_judgment_finding(self):
        scanner = [self._scanner_finding()]
        judged = [{
            "origin": "sec-sast-deep",
            "tool": "sec-sast-deep",
            "rule_id": "SAK-sast-deep-custom-rule",
            "file": "other/file.py",
            "line": 99,
            "message": "deep finding",
            "severity": "critical",
            "severity_source": "sec-sast-deep:critical",
            "decision": "real",
            "confidence": None,
            "evidence": {"sink": "other/file.py:99"},
        }]
        warnings = []
        result = evidence.merge_judgment(scanner, judged, warnings)
        assert len(result) == 2
        new = [f for f in result if f["dimension"] == "judgment"]
        assert len(new) == 1
        assert new[0]["file"] == "other/file.py"
        assert new[0]["line"] == 99
        assert new[0]["cvss"] is None

    def test_single_candidate_triage_match(self):
        """sec-triage with one candidate at the same location matches even without tool prefix."""
        scanner = [self._scanner_finding(tool="trivy", dimension="container")]
        judged = [{
            "origin": "sec-triage",
            "tool": "different-tool",
            "rule_id": "SAK-triage-x",
            "file": "src/app.py",
            "line": 42,
            "message": "triage note",
            "severity": "high",
            "severity_source": "sec-triage:high",
            "decision": "fp",
            "confidence": None,
            "evidence": {"sink": "src/app.py:42"},
        }]
        warnings = []
        result = evidence.merge_judgment(scanner, judged, warnings)
        # Should match the single candidate since origin is sec-triage
        assert len(result) == 1
        assert result[0]["decision"] == "fp"


# ---------------------------------------------------------------------------
# collect()
# ---------------------------------------------------------------------------
class TestCollect:
    def _make_sarif(self, tmp_path, results=None, rules=None):
        if results is None:
            results = [{
                "ruleId": "TEST-001",
                "message": {"text": "test finding"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/main.py"},
                        "region": {"startLine": 15},
                    }
                }],
            }]
        if rules is None:
            rules = [{
                "id": "TEST-001",
                "defaultConfiguration": {"level": "warning"},
            }]
        sarif = {
            "runs": [{
                "tool": {"driver": {"name": "test-tool", "rules": rules}},
                "results": results,
            }]
        }
        path = tmp_path / "test.sarif"
        path.write_text(json.dumps(sarif))
        return str(path)

    def test_basic_collection(self, tmp_path):
        path = self._make_sarif(tmp_path)
        warnings = []
        findings = evidence.collect(path, "semgrep", "sast", warnings)
        assert len(findings) == 1
        f = findings[0]
        assert f["tool"] == "semgrep"
        assert f["dimension"] == "sast"
        assert f["rule_id"] == "TEST-001"
        assert f["file"] == "src/main.py"
        assert f["line"] == 15
        assert f["message"] == "test finding"
        assert f["severity"] == "medium"  # warning -> medium

    def test_missing_file(self, tmp_path):
        warnings = []
        findings = evidence.collect(str(tmp_path / "missing.sarif"), "semgrep", "sast", warnings)
        assert findings == []

    def test_empty_runs(self, tmp_path):
        sarif = {"runs": []}
        path = tmp_path / "empty.sarif"
        path.write_text(json.dumps(sarif))
        warnings = []
        findings = evidence.collect(str(path), "semgrep", "sast", warnings)
        assert findings == []

    def test_no_results(self, tmp_path):
        sarif = {"runs": [{"tool": {"driver": {"rules": []}}}]}
        path = tmp_path / "noresults.sarif"
        path.write_text(json.dumps(sarif))
        warnings = []
        findings = evidence.collect(str(path), "semgrep", "sast", warnings)
        assert findings == []

    def test_result_without_rule_id(self, tmp_path):
        results = [{"message": {"text": "orphan"}}]
        path = self._make_sarif(tmp_path, results=results)
        warnings = []
        findings = evidence.collect(path, "semgrep", "sast", warnings)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "(none)"

    def test_cvss_passthrough_for_trivy(self, tmp_path):
        rules = [{"id": "CVE-1", "properties": {"security-severity": "9.8"}}]
        results = [{
            "ruleId": "CVE-1",
            "message": {"text": "critical vuln"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "Dockerfile"},
                    "region": {"startLine": 1},
                }
            }],
        }]
        path = self._make_sarif(tmp_path, results=results, rules=rules)
        warnings = []
        findings = evidence.collect(path, "trivy", "container", warnings)
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"
        assert findings[0]["cvss"] == 9.8


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------
class TestMain:
    def _write_sarif(self, sarif_dir, filename, results, rules=None):
        if rules is None:
            rules = []
        sarif = {
            "runs": [{
                "tool": {"driver": {"name": "test", "rules": rules}},
                "results": results,
            }]
        }
        path = os.path.join(sarif_dir, filename)
        with open(path, "w") as fh:
            json.dump(sarif, fh)

    def _write_summary(self, summary_path, dimensions):
        with open(summary_path, "w") as fh:
            json.dump({"dimensions": dimensions, "command": "scan.sh", "exit_code": 0}, fh)

    def test_end_to_end(self, tmp_path, monkeypatch):
        sarif_dir = str(tmp_path / "sarif")
        os.makedirs(sarif_dir)

        self._write_sarif(sarif_dir, "semgrep.sarif", results=[{
            "ruleId": "python.lang.security.sql-injection",
            "message": {"text": "Possible SQL injection"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "app/views.py"},
                    "region": {"startLine": 55},
                }
            }],
        }], rules=[{
            "id": "python.lang.security.sql-injection",
            "defaultConfiguration": {"level": "error"},
        }])

        summary_path = str(tmp_path / "summary.json")
        self._write_summary(summary_path, [{"name": "sast"}])

        out_path = str(tmp_path / "evidence.json")

        monkeypatch.setattr(sys, "argv", [
            "evidence.py",
            "--sarif-dir", sarif_dir,
            "--summary", summary_path,
            "--out", out_path,
        ])

        rc = evidence.main()
        assert rc == 0
        assert os.path.exists(out_path)

        with open(out_path) as fh:
            doc = json.load(fh)

        assert doc["schema"] == evidence.SCHEMA
        assert doc["counts"]["total"] == 1
        f = doc["findings"][0]
        assert f["tool"] == "semgrep"
        assert f["dimension"] == "sast"
        assert f["rule_id"] == "python.lang.security.sql-injection"
        assert f["file"] == "app/views.py"
        assert f["line"] == 55
        assert f["severity"] == "high"

    def test_end_to_end_with_findings(self, tmp_path, monkeypatch):
        sarif_dir = str(tmp_path / "sarif")
        os.makedirs(sarif_dir)

        self._write_sarif(sarif_dir, "semgrep.sarif", results=[{
            "ruleId": "R1",
            "message": {"text": "issue"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "app.py"},
                    "region": {"startLine": 10},
                }
            }],
        }], rules=[{
            "id": "R1",
            "defaultConfiguration": {"level": "warning"},
        }])

        summary_path = str(tmp_path / "summary.json")
        self._write_summary(summary_path, [{"name": "sast"}])

        findings_md = str(tmp_path / "findings.md")
        with open(findings_md, "w") as fh:
            fh.write(textwrap.dedent("""\
                # sec-triage

                | Sink (file:line) | Tool | Sev | Decision |
                |---|---|---|---|
                | app.py:10 | semgrep | medium | real |
            """))

        out_path = str(tmp_path / "evidence.json")
        monkeypatch.setattr(sys, "argv", [
            "evidence.py",
            "--sarif-dir", sarif_dir,
            "--summary", summary_path,
            "--out", out_path,
            "--findings", findings_md,
        ])

        rc = evidence.main()
        assert rc == 0

        with open(out_path) as fh:
            doc = json.load(fh)

        assert doc["counts"]["total"] == 1
        f = doc["findings"][0]
        assert f["decision"] == "real"

    def test_no_summary_includes_all(self, tmp_path, monkeypatch):
        """Without summary.json dimensions, all SARIF files on disk are included."""
        sarif_dir = str(tmp_path / "sarif")
        os.makedirs(sarif_dir)

        self._write_sarif(sarif_dir, "gitleaks.sarif", results=[{
            "ruleId": "generic-api-key",
            "message": {"text": "leaked key"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": ".env"},
                    "region": {"startLine": 1},
                }
            }],
        }])

        summary_path = str(tmp_path / "summary.json")
        # Write an empty summary (no dimensions)
        with open(summary_path, "w") as fh:
            json.dump({}, fh)

        out_path = str(tmp_path / "evidence.json")
        monkeypatch.setattr(sys, "argv", [
            "evidence.py",
            "--sarif-dir", sarif_dir,
            "--summary", summary_path,
            "--out", out_path,
        ])

        rc = evidence.main()
        assert rc == 0

        with open(out_path) as fh:
            doc = json.load(fh)

        assert doc["counts"]["total"] == 1
        assert any("no summary.json dimensions" in w for w in doc["warnings"])

    def test_deduplication(self, tmp_path, monkeypatch):
        sarif_dir = str(tmp_path / "sarif")
        os.makedirs(sarif_dir)

        # Two identical results (same rule, same location) should deduplicate
        dup_result = {
            "ruleId": "R1",
            "message": {"text": "dup"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "f.py"},
                    "region": {"startLine": 1},
                }
            }],
        }
        self._write_sarif(sarif_dir, "semgrep.sarif", results=[dup_result, dup_result])

        summary_path = str(tmp_path / "summary.json")
        self._write_summary(summary_path, [{"name": "sast"}])

        out_path = str(tmp_path / "evidence.json")
        monkeypatch.setattr(sys, "argv", [
            "evidence.py",
            "--sarif-dir", sarif_dir,
            "--summary", summary_path,
            "--out", out_path,
        ])

        rc = evidence.main()
        assert rc == 0

        with open(out_path) as fh:
            doc = json.load(fh)

        assert doc["counts"]["total"] == 1
        assert any("duplicate" in w for w in doc["warnings"])

    def test_dimension_aliases(self, tmp_path, monkeypatch):
        """'staged' is an alias for 'secret', so staged dimension includes gitleaks."""
        sarif_dir = str(tmp_path / "sarif")
        os.makedirs(sarif_dir)

        self._write_sarif(sarif_dir, "gitleaks.sarif", results=[{
            "ruleId": "G1",
            "message": {"text": "leak"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "config.py"},
                    "region": {"startLine": 3},
                }
            }],
        }])

        summary_path = str(tmp_path / "summary.json")
        self._write_summary(summary_path, [{"name": "staged"}])

        out_path = str(tmp_path / "evidence.json")
        monkeypatch.setattr(sys, "argv", [
            "evidence.py",
            "--sarif-dir", sarif_dir,
            "--summary", summary_path,
            "--out", out_path,
        ])

        rc = evidence.main()
        assert rc == 0

        with open(out_path) as fh:
            doc = json.load(fh)

        assert doc["counts"]["total"] == 1
        assert doc["findings"][0]["dimension"] == "secret"
