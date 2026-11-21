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
        assert "<tbody" in result

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

    def test_missing_evidence_is_a_failure_no_file(self, tmp_path, monkeypatch):
        # F04: asked to render with nothing to render from -> non-zero, so a caller can tell.
        ev = tmp_path / "nonexistent.json"
        out = tmp_path / "report.html"

        monkeypatch.setattr(
            "sys.argv",
            ["report_html.py", "--evidence", str(ev), "--out", str(out)],
        )
        rc = rh.main()
        assert rc == 1
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

    def test_dimension_status_chips_v2(self, tmp_path, monkeypatch):
        # summary.json schema 2 (F02): every status gets its own chip class, and the reason
        # travels with it, so a skipped dimension never reads as a quiet pass.
        dims = [
            {"name": "sast", "status": "findings", "gate": "block", "reason": None},
            {"name": "secret", "status": "skipped", "gate": "allow", "reason": "no docker -> gitleaks skipped"},
            {"name": "osv", "status": "error", "gate": "allow", "reason": "osv-scanner exit 2"},
            {"name": "iac", "status": "not_applicable", "gate": "allow", "reason": "no terraform"},
            {"name": "py-deps", "status": "indeterminate", "gate": "allow", "reason": "no venv"},
        ]
        doc = _minimal_evidence(scan={"command": "all", "exit_code": 1, "dimensions": dims})
        ev = self._write_evidence(tmp_path, doc)
        out = tmp_path / "report.html"
        monkeypatch.setattr("sys.argv", ["report_html.py", "--evidence", str(ev), "--out", str(out)])
        assert rh.main() == 0
        body = out.read_text(encoding="utf-8")
        for st in ("findings", "skipped", "error", "not_applicable", "indeterminate"):
            assert f'class="chip {st}"' in body
            assert f".chip.{st}" in body  # styled, not just tagged
        assert 'title="no docker -&gt; gitleaks skipped"' in body


# ---------------------------------------------------------------------------
# verdict() — F04: the header never says "clean" about something it cannot vouch for
# ---------------------------------------------------------------------------

class TestVerdict:
    P = {"name": "sast", "status": "pass", "gate": "allow"}

    def test_missing_exit_code_is_unknown(self):
        cls, text = rh.verdict({"dimensions": [self.P]}, 0)
        assert cls == "unknown" and "clean" not in text

    def test_null_exit_code_is_unknown(self):
        cls, text = rh.verdict({"exit_code": None, "dimensions": [self.P]}, 0)
        assert cls == "unknown" and "clean" not in text

    def test_exit_3_is_not_a_pass(self):
        cls, text = rh.verdict({"exit_code": 3, "dimensions": [self.P]}, 0)
        assert cls == "incomplete" and "not a pass" in text

    def test_exit_1_names_blockers_and_a_crash_is_not_a_finding(self):
        dims = [{"name": "sast", "status": "error", "gate": "block"},
                {"name": "py-deps", "status": "findings", "gate": "block"}]
        cls, text = rh.verdict({"exit_code": 1, "dimensions": dims}, 2)
        assert cls == "blocked"
        assert "sast (scan error, not a finding)" in text and "py-deps (findings)" in text

    def test_exit_1_schema1_still_blocked(self):
        cls, text = rh.verdict({"exit_code": 1, "dimensions": [{"name": "osv", "status": "fail"}]}, 1)
        assert cls == "blocked" and "exit 1" in text

    def test_exit_0_complete_and_no_findings_is_clean(self):
        dims = [self.P, {"name": "iac", "status": "not_applicable", "gate": "allow"}]
        cls, text = rh.verdict({"exit_code": 0, "dimensions": dims}, 0)
        assert cls == "clean"

    def test_exit_0_with_skipped_dimension_is_incomplete(self):
        dims = [self.P, {"name": "secret", "status": "skipped", "gate": "allow"}]
        cls, text = rh.verdict({"exit_code": 0, "dimensions": dims}, 0)
        assert cls == "incomplete" and "secret (skipped)" in text and "clean" not in text

    def test_exit_0_with_error_or_indeterminate_is_incomplete(self):
        for st in ("error", "indeterminate"):
            dims = [self.P, {"name": "osv", "status": st, "gate": "allow"}]
            cls, _ = rh.verdict({"exit_code": 0, "dimensions": dims}, 0)
            assert cls == "incomplete"

    def test_exit_0_without_dimensions_is_incomplete(self):
        cls, text = rh.verdict({"exit_code": 0, "dimensions": []}, 0)
        assert cls == "incomplete" and "coverage unknown" in text

    def test_exit_0_with_soft_findings_is_not_clean(self):
        dims = [self.P, {"name": "container", "status": "findings", "gate": "allow"}]
        cls, text = rh.verdict({"exit_code": 0, "dimensions": dims}, 3)
        assert cls == "findings" and "none blocking" in text


class TestScanTime:
    SCAN = {"dimensions": [{"name": "sast", "status": "pass"}], "artifacts": [{"path": "sarif/semgrep.sarif", "sha256": "a"}],
            "provenance": {"commit": "c1"}}

    def test_same_run_gives_its_timestamp(self):
        summary = dict(self.SCAN, timestamp="2026-11-02T10:00:00", run_id="r1")
        assert rh.scan_time(summary, self.SCAN) == ("2026-11-02T10:00:00", "r1")

    def test_later_run_summary_is_not_used(self):
        summary = dict(self.SCAN, timestamp="2026-11-03T10:00:00", run_id="r2",
                       dimensions=[{"name": "secret", "status": "pass"}])
        assert rh.scan_time(summary, self.SCAN) is None

    def test_no_summary(self):
        assert rh.scan_time(None, self.SCAN) is None


class TestHonestHeader:
    def _render(self, tmp_path, monkeypatch, scan, summary=None):
        ev = tmp_path / "evidence.json"
        ev.write_text(json.dumps(_minimal_evidence(scan=scan)), encoding="utf-8")
        out = tmp_path / "report.html"
        argv = ["report_html.py", "--evidence", str(ev), "--out", str(out), "--date", "2026-11-05"]
        if summary is not None:
            sp = tmp_path / "summary.json"
            sp.write_text(json.dumps(summary), encoding="utf-8")
            argv += ["--summary", str(sp)]
        monkeypatch.setattr("sys.argv", argv)
        assert rh.main() == 0
        return out.read_text(encoding="utf-8")

    def test_skipped_dimension_never_reads_clean(self, tmp_path, monkeypatch):
        scan = {"command": "all", "exit_code": 0,
                "dimensions": [{"name": "secret", "status": "skipped", "gate": "allow", "reason": "no docker"}]}
        body = self._render(tmp_path, monkeypatch, scan)
        assert "clean (exit 0)" not in body and "NOT complete" in body

    def test_scan_and_report_dates_are_separate(self, tmp_path, monkeypatch):
        scan = {"command": "all", "exit_code": 0, "dimensions": [{"name": "sast", "status": "pass"}]}
        summary = dict(scan, timestamp="2026-11-02T10:00:00", run_id="20261102T100000-1")
        body = self._render(tmp_path, monkeypatch, scan, summary)
        assert "Scanned 2026-11-02T10:00:00" in body and "report generated 2026-11-05" in body

    def test_unknown_scan_time_is_said(self, tmp_path, monkeypatch):
        scan = {"command": "all", "exit_code": 0, "dimensions": [{"name": "sast", "status": "pass"}]}
        body = self._render(tmp_path, monkeypatch, scan)
        assert "scan time unknown" in body


class TestScanTimeIgnoresDurations:
    def test_summary_with_seconds_still_matches_its_evidence(self):
        scan = {"dimensions": [{"name": "sast", "status": "pass"}], "artifacts": [], "provenance": {"commit": "c"}}
        summary = {"dimensions": [{"name": "sast", "status": "pass", "seconds": 2.5}], "artifacts": [],
                   "provenance": {"commit": "c"}, "timestamp": "2026-11-02T10:00:00", "run_id": "r"}
        assert rh.scan_time(summary, scan) == ("2026-11-02T10:00:00", "r")


class TestVerdictFindingsWithoutRows:
    """F16: a dimension with findings but no per-finding rows must not be reported as 0 findings."""

    def test_iac_findings_with_no_rows_are_named_not_counted_as_zero(self):
        dims = [{"name": "sast", "status": "pass"}, {"name": "iac", "status": "findings"}]
        cls, text = rh.verdict({"exit_code": 0, "dimensions": dims}, 0, set())
        assert cls == "findings" and "iac" in text and "0 finding" not in text

    def test_rows_listed_alongside_an_unlisted_dimension(self):
        dims = [{"name": "sast", "status": "findings"}, {"name": "py-deps", "status": "findings"}]
        cls, text = rh.verdict({"exit_code": 0, "dimensions": dims}, 3, {"sast"})
        assert "py-deps" in text and "sast" not in text.split("findings in")[1].split(",")[0] and "3 more listed" in text

    def test_alias_dimension_counts_as_listed(self):
        dims = [{"name": "staged", "status": "findings"}]
        cls, text = rh.verdict({"exit_code": 0, "dimensions": dims}, 1, {"secret"})
        assert text == "passed (exit 0) — 1 finding(s) present, none blocking"

    def test_old_callers_without_row_dims_keep_their_header_when_rows_exist(self):
        dims = [{"name": "sast", "status": "findings"}]
        _, text = rh.verdict({"exit_code": 0, "dimensions": dims}, 2, {"sast"})
        assert text == "passed (exit 0) — 2 finding(s) present, none blocking"



# ---------------------------------------------------------------------------
# F26 — filters, details, CSP
# ---------------------------------------------------------------------------
import base64 as _b64
import hashlib as _hl
import re as _re
import subprocess as _sp


def _render(tmp_path, findings, name="r.html"):
    ev = {"schema": "security-audit-kit/evidence@1", "scan": {"exit_code": 0, "dimensions": []},
          "counts": {"total": len(findings), "by_severity": {}, "by_decision": {}}, "findings": findings}
    (tmp_path / "e.json").write_text(json.dumps(ev))
    out = tmp_path / name
    _sp.run([sys.executable, os.path.join(os.path.dirname(rh.__file__), "report_html.py"), "--evidence",
             str(tmp_path / "e.json"), "--out", str(out), "--date", "2026-01-01"], check=True, capture_output=True)
    return out.read_text()


def _f(**kw):
    f = {"id": "abc", "severity": "high", "tool": "semgrep", "rule_id": "R", "file": "a.py", "line": 3,
         "message": "m", "decision": None, "confidence": None, "evidence": None}
    f.update(kw)
    return f


class TestReportFilters:
    def test_csp_pins_the_one_script_by_hash(self, tmp_path):
        page = _render(tmp_path, [_f()])
        scripts = _re.findall(r"<script>(.*?)</script>", page, _re.S)
        assert len(scripts) == 1 and "<script src" not in page
        digest = _b64.b64encode(_hl.sha256(scripts[0].encode()).digest()).decode()
        csp = _re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', page).group(1)
        assert f"script-src 'sha256-{digest}'" in csp and "default-src 'none'" in csp

    def test_the_form_ships_hidden_so_no_js_shows_no_dead_control(self, tmp_path):
        page = _render(tmp_path, [_f()])
        assert _re.search(r'<form id="filters"[^>]*\bhidden\b', page)

    def test_no_findings_no_form(self, tmp_path):
        assert 'id="filters"' not in _render(tmp_path, [])

    def test_options_are_only_the_values_present(self, tmp_path):
        page = _render(tmp_path, [_f(tool="gitleaks", severity="critical"), _f(id="b", tool="semgrep", decision="fp")])
        sel = lambda n: _re.findall(r'<option value="([^"]*)">', _re.search(f'<select name="{n}">(.*?)</select>', page, _re.S).group(1))
        assert sel("sev") == ["", "critical", "high"] and sel("tool") == ["", "gitleaks", "semgrep"]
        assert sel("dec") == ["", "fp", "none"]

    def test_rows_carry_escaped_filter_attributes(self, tmp_path):
        page = _render(tmp_path, [_f(tool='x"><script>alert(1)</script>', decision="real")])
        assert 'data-tool="x&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"' in page and 'data-dec="real"' in page
        assert page.count("<script>") == 1

    def test_no_match_says_it_is_not_a_clean_result(self, tmp_path):
        page = _render(tmp_path, [_f()])
        assert '<tr class="nomatch" hidden>' in page and "not a clean result" in page

    def test_details_show_adapter_fields_escaped(self, tmp_path):
        page = _render(tmp_path, [_f(package={"ecosystem": "npm", "name": "<b>x</b>", "version": None},
                                     fixed_in=["1.2.8"], aliases=["CVE-1"], direct=True)])
        assert "<details class=\"more\">" in page and "&lt;b&gt;x&lt;/b&gt;" in page and "1.2.8" in page
        assert "<dt>direct</dt><dd>yes</dd>" in page

    def test_a_row_with_only_an_id_gets_no_toggle(self, tmp_path):
        assert "<details" not in _render(tmp_path, [_f()])

    def test_counts_are_addressable_for_the_script(self, tmp_path):
        page = _render(tmp_path, [_f(), _f(id="s", decision="suppressed")])
        assert '<span id="count-reported" aria-live="polite">1</span>' in page
        assert '<span id="count-suppressed" aria-live="polite">1</span>' in page

    def test_rendering_is_deterministic(self, tmp_path):
        fs = [_f(), _f(id="b", tool="trivy", package={"ecosystem": "pypi", "name": "x"})]
        assert _render(tmp_path, fs, "a.html") == _render(tmp_path, fs, "b.html")
