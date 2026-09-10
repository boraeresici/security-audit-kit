"""Tests for lib/report_html.py — HTML report renderer."""
from __future__ import annotations

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "lib"))

import report_html as rh


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_evidence(findings=None, **overrides):
    """Return a valid evidence dict with sensible defaults."""
    doc = {
        "schema": "security-audit-kit/evidence@1",
        "scan": {
            "command": "scan.sh --repo demo",
            "exit_code": 1,
            "dimensions": [{"name": "sec-sast-deep", "status": "pass"}],
        },
        "counts": {
            "total": len(findings or []),
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "by_decision": {"real": 0, "fp": 0, "uncertain": 0, "suppressed": 0, "undecided": 0},
        },
        "findings": findings or [],
    }
    doc.update(overrides)
    return doc


def _sample_finding(**overrides):
    f = {
        "id": "sak-001",
        "severity": "high",
        "severity_source": "tool",
        "tool": "sec-sast-deep",
        "rule_id": "sec-sast-deep/idor",
        "file": "src/api.py",
        "line": 42,
        "message": "IDOR on /api/users/{id}",
        "confidence": 0.9,
        "cvss": 7.5,
        "decision": None,
        "evidence": {"source": "user_id from query param", "note": "no ownership check"},
        "dimension": "judgment",
    }
    f.update(overrides)
    return f


# ===========================================================================
# 1. esc()
# ===========================================================================

class TestEsc:
    def test_none_returns_empty(self):
        assert rh.esc(None) == ""

    def test_script_tag_escaped(self):
        assert rh.esc("<script>") == "&lt;script&gt;"

    def test_normal_text_unchanged(self):
        assert rh.esc("hello world") == "hello world"

    def test_ampersand_escaped(self):
        assert rh.esc("a&b") == "a&amp;b"

    def test_numeric_converted_to_str(self):
        assert rh.esc(42) == "42"


# ===========================================================================
# 2. location()
# ===========================================================================

class TestLocation:
    def test_file_and_line(self):
        assert rh.location({"file": "src/app.py", "line": 42}) == "src/app.py:42"

    def test_file_without_line(self):
        assert rh.location({"file": "src/app.py"}) == "src/app.py"

    def test_none_file_returns_dash(self):
        assert rh.location({"file": None}) == "\u2014"

    def test_missing_file_returns_dash(self):
        assert rh.location({}) == "\u2014"

    def test_empty_string_file_returns_dash(self):
        assert rh.location({"file": ""}) == "\u2014"

    def test_line_zero_treated_as_absent(self):
        # line=0 is falsy → should return just the path
        assert rh.location({"file": "x.py", "line": 0}) == "x.py"


# ===========================================================================
# 3. severity_bars()
# ===========================================================================

class TestSeverityBars:
    def test_all_severity_levels_present(self):
        counts = {"critical": 2, "high": 3, "medium": 1, "low": 0, "info": 4}
        result = rh.severity_bars(counts, total=10)
        for sev in rh.SEVERITY_ORDER:
            assert sev in result
        assert 'class="bars"' in result
        assert 'class="bar"' in result

    def test_zero_total_no_zero_division(self):
        result = rh.severity_bars({}, total=0)
        assert 'class="bars"' in result
        assert "0.0%" in result  # all widths are 0

    def test_width_proportional(self):
        counts = {"critical": 5, "high": 0, "medium": 0, "low": 0, "info": 0}
        result = rh.severity_bars(counts, total=10)
        assert "50.0%" in result  # 5/10

    def test_opacity_dim_when_zero(self):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        result = rh.severity_bars(counts, total=0)
        assert ".18" in result  # dimmed opacity for zero-count bars


# ===========================================================================
# 4. finding_rows()
# ===========================================================================

class TestFindingRows:
    def test_empty_list(self):
        result = rh.finding_rows([])
        assert "Nothing in this section" in result

    def test_evidence_source_and_note(self):
        f = _sample_finding()
        result = rh.finding_rows([f])
        assert "source: user_id from query param" in result
        assert "no ownership check" in result

    def test_note_skipped_when_equals_message(self):
        f = _sample_finding(message="same text", evidence={"source": "x", "note": "same text"})
        result = rh.finding_rows([f])
        assert "source: x" in result
        # The note should NOT appear as a separate detail because it equals the message
        assert result.count("same text") == 1

    def test_cvss_shown(self):
        f = _sample_finding(cvss=7.5)
        result = rh.finding_rows([f])
        assert "CVSS 7.5" in result

    def test_no_cvss(self):
        f = _sample_finding(cvss=None)
        result = rh.finding_rows([f])
        assert "CVSS" not in result

    def test_confidence_shown(self):
        f = _sample_finding(confidence=0.85)
        result = rh.finding_rows([f])
        assert "0.85" in result

    def test_confidence_absent_shows_dash(self):
        f = _sample_finding(confidence=None)
        result = rh.finding_rows([f])
        assert "conf \u2014" in result

    def test_severity_class(self):
        f = _sample_finding(severity="critical")
        result = rh.finding_rows([f])
        assert 'sev critical' in result


# ===========================================================================
# 5. table()
# ===========================================================================

class TestTable:
    def test_wraps_in_panel_and_table(self):
        result = rh.table([])
        assert 'class="panel scroll"' in result
        assert "<table>" in result
        assert "<thead>" in result
        assert "<tbody>" in result

    def test_correct_headers(self):
        result = rh.table([])
        for header in ("Severity", "Tool / rule", "Location", "Finding", "Decision"):
            assert f"<th>{header}</th>" in result

    def test_rows_embedded(self):
        f = _sample_finding()
        result = rh.table([f])
        assert "IDOR on /api/users/{id}" in result


# ===========================================================================
# 6. main() — end-to-end
# ===========================================================================

class TestMain:
    def _write_evidence(self, tmp_path, doc):
        ev = tmp_path / "evidence.json"
        ev.write_text(json.dumps(doc), encoding="utf-8")
        return ev

    def test_normal_findings(self, tmp_path, monkeypatch):
        finding = _sample_finding()
        doc = _minimal_evidence(findings=[finding])
        ev = self._write_evidence(tmp_path, doc)
        out = tmp_path / "report.html"

        monkeypatch.setattr(
            "sys.argv",
            ["report_html.py", "--evidence", str(ev), "--out", str(out), "--repo", "demo", "--date", "2026-09-10"],
        )
        rc = rh.main()
        assert rc == 0
        assert out.exists()
        body = out.read_text(encoding="utf-8")
        assert "IDOR on /api/users/{id}" in body
        assert "demo" in body
        assert "2026-09-10" in body

    def test_suppressed_findings_in_suppressed_section(self, tmp_path, monkeypatch):
        reported = _sample_finding(id="sak-001", decision="real")
        suppressed = _sample_finding(
            id="sak-002", decision="suppressed",
            message="Suppressed issue", severity="low",
        )
        doc = _minimal_evidence(findings=[reported, suppressed])
        ev = self._write_evidence(tmp_path, doc)
        out = tmp_path / "report.html"

        monkeypatch.setattr(
            "sys.argv",
            ["report_html.py", "--evidence", str(ev), "--out", str(out)],
        )
        rc = rh.main()
        assert rc == 0
        body = out.read_text(encoding="utf-8")
        # Suppressed heading present
        assert "Suppressed" in body
        assert "Suppressed issue" in body

    def test_missing_evidence_returns_zero_no_file(self, tmp_path, monkeypatch):
        ev = tmp_path / "nonexistent.json"
        out = tmp_path / "report.html"

        monkeypatch.setattr(
            "sys.argv",
            ["report_html.py", "--evidence", str(ev), "--out", str(out)],
        )
        rc = rh.main()
        assert rc == 0
        assert not out.exists()

    def test_invalid_schema_returns_one(self, tmp_path, monkeypatch):
        doc = {"schema": "something/else@2", "findings": []}
        ev = self._write_evidence(tmp_path, doc)
        out = tmp_path / "report.html"

        monkeypatch.setattr(
            "sys.argv",
            ["report_html.py", "--evidence", str(ev), "--out", str(out)],
        )
        rc = rh.main()
        assert rc == 1
        assert not out.exists()

    def test_invalid_json_returns_one(self, tmp_path, monkeypatch):
        ev = tmp_path / "evidence.json"
        ev.write_text("{not valid json", encoding="utf-8")
        out = tmp_path / "report.html"

        monkeypatch.setattr(
            "sys.argv",
            ["report_html.py", "--evidence", str(ev), "--out", str(out)],
        )
        rc = rh.main()
        assert rc == 1
