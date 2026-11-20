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
# F42: the findings table is model-written, so its cells are untrusted input
# ---------------------------------------------------------------------------
def _one_row(tmp_path, loc, why="ok"):
    md = tmp_path / "findings.md"
    md.write_text(f"# sec-sast-deep\n\n| Sink (file:line) | Sev | Why |\n|---|---|---|\n| {loc} | high | {why} |\n",
                  encoding="utf-8")
    warnings = []
    return evidence.parse_findings_md(str(md), warnings), warnings


class TestJudgmentInputSafety:
    @pytest.mark.parametrize("loc", [
        "/etc/passwd:1",
        "~/x.py:3",
        "../outside.py:4",
        "src/../../x.py:4",
        "src/./x.py:4",
        "src//x.py:4",
        "src/:4",
        "C:/repo/x.py:5",
        "c:x.py:5",
        "src\\app.py:6",
        "src/app.py:0",
        "src/a\x07pp.py:7",
        "src/\u202eyp.exe:8",
        "src/a\u200bpp.py:8",
        "src/a\u2028pp.py:8",
        # from the review of the first version
        "https:/evil.example/x.py:3",
        "javascript:alert(1)",
        "file:etc/passwd:3",
        "a.py:" + "9" * 5000,
        "a.py:99999999999",
        "src/app.py:10000001",
        "a/ /b.py:1",
        "a/\u3000/b.py:1",
        "a/.. /b.py:1",
        "a/.../b.py:1",
        "a/file.:1",
        "x/\u3164.py:1",
        "x/\ue000y.py:1",
        "\uff0e\uff0e/\uff0e\uff0e/x.py:1",
        "s" * 1025,
    ])
    def test_unsafe_location_is_dropped_and_said(self, tmp_path, loc):
        results, warnings = _one_row(tmp_path, loc)
        assert results == []
        assert any("not a safe repo-relative path" in w for w in warnings)

    def test_warning_escapes_what_it_quotes(self, tmp_path):
        _, warnings = _one_row(tmp_path, "src/\u202eyp.exe:8")
        assert all("\u202e" not in w for w in warnings)
        assert any("\\u202e" in w for w in warnings)

    @pytest.mark.parametrize("loc,path,line", [
        ("src/app.py:42", "src/app.py", 42),
        ("`src/app.py:42`", "src/app.py", 42),
        ("./src/app.py:42", "src/app.py", 42),
        ("src/app.py", "src/app.py", None),
        ("docs/ünïcode/naïve.py:3", "docs/ünïcode/naïve.py", 3),
        (".github/workflows/ci.yml:9", ".github/workflows/ci.yml", 9),
        ("src/app.py:12:5", "src/app.py", 12),
        ("cafe\u0301/menu.py:2", "cafe\u0301/menu.py", 2),     # NFD, as macOS writes it
        ("my docs/read me.md:4", "my docs/read me.md", 4),
        ("src/%2e%2e/x.py:1", "src/%2e%2e/x.py", 1),          # literal name; encoded at the SARIF sink
    ])
    def test_normal_location_still_passes(self, tmp_path, loc, path, line):
        results, warnings = _one_row(tmp_path, loc)
        assert [(r["file"], r["line"]) for r in results] == [(path, line)]
        assert warnings == []

    def test_non_ascii_digit_is_not_a_line_and_does_not_crash(self, tmp_path):
        results, warnings = _one_row(tmp_path, "src/app.py:²")
        assert results == [] and any("not a safe" in w for w in warnings)

    def test_free_text_loses_control_and_bidi_characters(self, tmp_path):
        results, _ = _one_row(tmp_path, "src/app.py:1", why="see\x1b[31m red\u202e evil\u200b\u2029end")
        assert results[0]["message"] == "see [31m red evil end"
        assert results[0]["evidence"]["note"] == "see [31m red evil end"

    def test_free_text_keeps_joiners_that_belong_to_the_text(self, tmp_path):
        text = "m\u06cc\u200c\u062e\u0648\u0627\u0647\u0645 \U0001f469\u200d\U0001f4bb co\u00adop"
        results, _ = _one_row(tmp_path, "src/app.py:1", why=text)
        assert results[0]["message"] == text

    @pytest.mark.parametrize("loc", ["N/A", "\u2013", "none"])
    def test_placeholder_location_is_not_a_file(self, tmp_path, loc):
        results, warnings = _one_row(tmp_path, loc)
        assert results == [] and warnings == []

    def test_row_warnings_are_capped(self, tmp_path):
        md = tmp_path / "findings.md"
        md.write_text("# sec-sast-deep\n\n| Sink (file:line) | Sev |\n|---|---|\n" + "| /x | high |\n" * 500)
        warnings = []
        assert evidence.parse_findings_md(str(md), warnings) == []
        assert len(warnings) == evidence.MAX_ROW_WARNINGS + 1
        assert "480 more rows dropped" in warnings[-1]

    @pytest.mark.parametrize("conf", ["nan", "inf", "-inf", "1e999", "999", "-0.1", "1_0"])
    def test_confidence_outside_0_1_is_none_and_said(self, tmp_path, conf):
        md = tmp_path / "findings.md"
        md.write_text(f"# sec-sast-deep\n\n| Sink (file:line) | Sev | Conf |\n|---|---|---|\n| a.py:1 | high | {conf} |\n")
        warnings = []
        results = evidence.parse_findings_md(str(md), warnings)
        assert results[0]["confidence"] is None and any("not in [0, 1]" in w for w in warnings)
        json.dumps(results, allow_nan=False)

    def test_severity_cell_is_capped_in_severity_source(self, tmp_path):
        md = tmp_path / "findings.md"
        md.write_text("# sec-sast-deep\n\n| Sink (file:line) | Sev |\n|---|---|\n| a.py:1 | " + "z" * 3000 + " |\n")
        warnings = []
        results = evidence.parse_findings_md(str(md), warnings)
        assert len(results[0]["severity_source"]) <= len("sec-sast-deep:") + 40
        assert all(len(w) < 200 for w in warnings)

    def test_bom_prefixed_file_is_read(self, tmp_path):
        md = tmp_path / "findings.md"
        md.write_bytes("\ufeff| Sink (file:line) | Sev |\n|---|---|\n| a.py:1 | high |\n".encode("utf-8"))
        assert [r["file"] for r in evidence.parse_findings_md(str(md), [])] == ["a.py"]

    def test_free_text_is_capped(self, tmp_path):
        results, _ = _one_row(tmp_path, "src/app.py:1", why="x" * 5000)
        msg = results[0]["message"]
        assert len(msg) == evidence.MAX_CELL_CHARS and msg.endswith("…")

    def test_oversized_findings_file_skips_the_judgment_layer(self, tmp_path, monkeypatch):
        monkeypatch.setattr(evidence, "MAX_FINDINGS_BYTES", 64)
        results, warnings = _one_row(tmp_path, "src/app.py:1", why="x" * 100)
        assert results == []
        assert any("judgment layer skipped" in w for w in warnings)

    def test_undecodable_findings_file_is_said_not_raised(self, tmp_path):
        md = tmp_path / "findings.md"
        md.write_bytes(b"| Sink | Sev |\n|---|---|\n| a.py:1 | \xff\xfe |\n")
        warnings = []
        assert evidence.parse_findings_md(str(md), warnings) == []
        assert any("UnicodeDecodeError" in w for w in warnings)


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


# ---------------------------------------------------------------------------
# select_sources() — F03: only this run's outputs, from dimensions that inspected something
# ---------------------------------------------------------------------------

class TestSelectSources:
    RESULT = {"ruleId": "R1", "message": {"text": "m"},
              "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"},
                                                  "region": {"startLine": 1}}}]}

    def _sarif(self, d, name):
        p = os.path.join(d, name)
        with open(p, "w") as fh:
            json.dump({"runs": [{"tool": {"driver": {"name": "t"}}, "results": [self.RESULT]}]}, fh)
        return p

    def _sha(self, p):
        import hashlib
        with open(p, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()

    def _summary(self, dims, artifacts, sarif=True):
        return {"schema_version": 2, "sarif": sarif, "dimensions": dims, "artifacts": artifacts}

    def _art(self, p):
        return {"path": "sarif/" + os.path.basename(p), "sha256": self._sha(p)}

    def test_manifest_file_of_inspecting_dimension_is_used(self, tmp_path):
        p = self._sarif(tmp_path, "semgrep.sarif")
        w = []
        got = evidence.select_sources(self._summary([{"name": "sast", "status": "findings"}], [self._art(p)]),
                                      str(tmp_path), w)
        assert got == [(p, "semgrep", "sast")]
        assert w == []

    def test_leftover_file_not_in_manifest_is_ignored_and_said(self, tmp_path):
        # The measured shape: yesterday's semgrep.sarif on disk, today sast was skipped.
        self._sarif(tmp_path, "semgrep.sarif")
        w = []
        got = evidence.select_sources(self._summary([{"name": "sast", "status": "skipped"}], []), str(tmp_path), w)
        assert got == []
        assert any("semgrep.sarif" in x and "not produced by this run" in x for x in w)

    def test_error_status_output_is_not_current_findings(self, tmp_path):
        p = self._sarif(tmp_path, "semgrep.sarif")
        w = []
        got = evidence.select_sources(self._summary([{"name": "sast", "status": "error"}], [self._art(p)]),
                                      str(tmp_path), w)
        assert got == []
        assert any("sast" in x and "error" in x for x in w)

    def test_changed_after_the_scan_is_rejected(self, tmp_path):
        p = self._sarif(tmp_path, "semgrep.sarif")
        art = self._art(p)
        with open(p, "a") as fh:
            fh.write(" ")
        w = []
        got = evidence.select_sources(self._summary([{"name": "sast", "status": "pass"}], [art]), str(tmp_path), w)
        assert got == []
        assert any("changed since" in x for x in w)

    def test_listed_but_missing_is_said(self, tmp_path):
        w = []
        art = {"path": "sarif/semgrep.sarif", "sha256": "0" * 64}
        got = evidence.select_sources(self._summary([{"name": "sast", "status": "pass"}], [art]), str(tmp_path), w)
        assert got == []
        assert any("missing" in x for x in w)

    def test_inspecting_dimension_without_sarif_is_said(self, tmp_path):
        w = []
        evidence.select_sources(self._summary([{"name": "secret", "status": "pass"}], []), str(tmp_path), w)
        assert any("secret" in x and "no per-finding output" in x for x in w)

    def test_alias_dimension_uses_its_tools_file(self, tmp_path):
        p = self._sarif(tmp_path, "gitleaks.sarif")
        got = evidence.select_sources(self._summary([{"name": "staged", "status": "pass"}], [self._art(p)]),
                                      str(tmp_path), [])
        assert got == [(p, "gitleaks", "secret")]

    def test_schema1_summary_keeps_the_old_scoping(self, tmp_path):
        p = self._sarif(tmp_path, "semgrep.sarif")
        self._sarif(tmp_path, "gitleaks.sarif")
        w = []
        got = evidence.select_sources({"dimensions": [{"name": "sast", "status": "fail"}]}, str(tmp_path), w)
        assert got == [(p, "semgrep", "sast")]
        assert any("no artifact manifest" in x for x in w)

    def test_provenance_is_carried_into_evidence(self, tmp_path, monkeypatch):
        p = self._sarif(tmp_path, "semgrep.sarif")
        prov = {"commit": "abc", "dirty": False, "kit": {"version": "9.9.9"}}
        summary = self._summary([{"name": "sast", "status": "findings"}], [self._art(p)])
        summary["provenance"] = prov
        summary["run_id"] = "20261102T000000-1"
        sp, out = tmp_path / "summary.json", tmp_path / "evidence.json"
        sp.write_text(json.dumps(summary))
        monkeypatch.setattr(sys, "argv", ["evidence.py", "--sarif-dir", str(tmp_path), "--summary", str(sp),
                                          "--out", str(out)])
        assert evidence.main() == 0
        doc = json.loads(out.read_text())
        assert doc["scan"]["provenance"] == prov
        assert doc["counts"]["total"] == 1
        assert "run_id" not in json.dumps(doc)  # run metadata stays in summary.json: evidence is diffable


class TestRunTimingStaysOut:
    def test_dimension_seconds_are_not_copied_into_evidence(self, tmp_path, monkeypatch):
        # F14a: summary.json times each dimension; evidence.json must still diff to nothing on
        # unchanged code, so the per-run duration stays in summary.json.
        summary = {"schema_version": 2, "sarif": True, "artifacts": [],
                   "dimensions": [{"name": "sast", "status": "pass", "gate": "allow", "seconds": 3.1}]}
        sp, out = tmp_path / "summary.json", tmp_path / "evidence.json"
        sp.write_text(json.dumps(summary))
        monkeypatch.setattr(sys, "argv", ["evidence.py", "--sarif-dir", str(tmp_path), "--summary", str(sp),
                                          "--out", str(out)])
        assert evidence.main() == 0
        doc = json.loads(out.read_text())
        assert doc["scan"]["dimensions"] == [{"name": "sast", "status": "pass", "gate": "allow"}]


class TestMergeToolTiebreak:
    def test_dash_tool_cell_does_not_claim_a_scanner_finding(self):
        scanner = [{"id": "g1", "tool": "gitleaks", "file": "cfg.py", "line": 3, "decision": None},
                   {"id": "s1", "tool": "semgrep", "file": "cfg.py", "line": 3, "decision": None}]
        judged = [{"origin": "sec-sast-deep", "tool": "-", "rule_id": "SAK-sast-deep-x", "file": "cfg.py", "line": 3,
                   "message": "m", "severity": "low", "severity_source": "s", "decision": "suppressed",
                   "confidence": None, "evidence": {}}]
        out = evidence.merge_judgment(scanner, judged, [])
        assert [f["decision"] for f in out[:2]] == [None, None]
        assert out[2]["dimension"] == "judgment"


class TestNumericSeverityFinite:
    @pytest.mark.parametrize("raw", ["NaN", "nan", "inf", "-Infinity"])
    def test_non_finite_score_is_ignored(self, raw):
        assert evidence.numeric_severity({"properties": {"security-severity": raw}}) is None


class TestNoAdapterWarning:
    def test_findings_dimension_without_an_adapter_is_said(self, tmp_path):
        summary = {"schema": 2, "sarif": True, "artifacts": {},
                   "dimensions": [{"name": "js-deps", "status": "findings"}, {"name": "guarddog", "status": "pass"}]}
        warnings = []
        evidence.select_sources(summary, str(tmp_path), warnings)
        assert any(w.startswith("js-deps: has findings, but the kit reads no per-finding output") for w in warnings)
        assert not any(w.startswith("guarddog:") for w in warnings)


class TestToolSuppression:
    """semgrep writes `nosemgrep` hits into its SARIF with suppressions: [{kind: inSource}]."""

    def _sarif(self, tmp_path, suppressions):
        result = {"ruleId": "R", "level": "error", "message": {"text": "m"},
                  "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 2}}}]}
        if suppressions is not None:
            result["suppressions"] = suppressions
        p = tmp_path / "semgrep.sarif"
        p.write_text(json.dumps({"runs": [{"tool": {"driver": {"name": "semgrep", "rules": []}}, "results": [result]}]}))
        return evidence.collect(str(p), "semgrep", "sast", [])[0]

    def test_in_source_suppression_is_recorded_as_suppressed(self, tmp_path):
        f = self._sarif(tmp_path, [{"kind": "inSource"}])
        assert f["decision"] == "suppressed" and "inSource" in f["evidence"]["note"]

    def test_justification_is_kept(self, tmp_path):
        f = self._sarif(tmp_path, [{"kind": "external", "justification": "test fixture"}])
        assert f["evidence"]["note"].endswith(": test fixture")

    @pytest.mark.parametrize("status", ["rejected", "underReview"])
    def test_a_suppression_not_accepted_leaves_the_finding_live(self, tmp_path, status):
        assert self._sarif(tmp_path, [{"kind": "inSource", "status": status}])["decision"] is None

    def test_no_suppression_is_unchanged(self, tmp_path):
        f = self._sarif(tmp_path, None)
        assert f["decision"] is None and f["evidence"] is None
