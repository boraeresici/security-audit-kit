"""Tests for lib/kit_sarif.py — SARIF 2.1.0 renderer for judgment findings."""
from __future__ import annotations

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "lib"))

import kit_sarif as ks


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sample_finding(**overrides):
    f = {
        "id": "sak-001",
        "severity": "high",
        "tool": "sec-sast-deep",
        "rule_id": "sec-sast-deep/idor",
        "file": "src/api.py",
        "line": 42,
        "message": "IDOR on /api/users/{id}",
        "confidence": 0.9,
        "decision": None,
        "dimension": "judgment",
        "evidence": {"source": "user_id from query param", "note": "no ownership check"},
    }
    f.update(overrides)
    return f


def _minimal_evidence(findings=None, **overrides):
    doc = {
        "schema": "security-audit-kit/evidence@1",
        "findings": findings or [],
    }
    doc.update(overrides)
    return doc


# ===========================================================================
# 1. rule_for()
# ===========================================================================

class TestRuleFor:
    def test_id_matches_rule_id(self):
        f = _sample_finding()
        rule = ks.rule_for(f)
        assert rule["id"] == "sec-sast-deep/idor"

    def test_level_critical_maps_to_error(self):
        rule = ks.rule_for(_sample_finding(severity="critical"))
        assert rule["defaultConfiguration"]["level"] == "error"

    def test_level_medium_maps_to_warning(self):
        rule = ks.rule_for(_sample_finding(severity="medium"))
        assert rule["defaultConfiguration"]["level"] == "warning"

    def test_level_low_maps_to_note(self):
        rule = ks.rule_for(_sample_finding(severity="low"))
        assert rule["defaultConfiguration"]["level"] == "note"

    def test_level_info_maps_to_none(self):
        rule = ks.rule_for(_sample_finding(severity="info"))
        assert rule["defaultConfiguration"]["level"] == "none"

    def test_level_unknown_defaults_to_warning(self):
        rule = ks.rule_for(_sample_finding(severity="unknown"))
        assert rule["defaultConfiguration"]["level"] == "warning"

    def test_tags_include_tool_name(self):
        f = _sample_finding(tool="sec-ai-review")
        rule = ks.rule_for(f)
        assert "sec-ai-review" in rule["properties"]["tags"]

    def test_tags_include_security_and_kit(self):
        rule = ks.rule_for(_sample_finding())
        tags = rule["properties"]["tags"]
        assert "security" in tags
        assert "security-audit-kit" in tags

    def test_short_description_from_skill(self):
        f = _sample_finding(tool="sec-sast-deep")
        rule = ks.rule_for(f)
        assert "Semantic SAST" in rule["shortDescription"]["text"]

    def test_fallback_tool_name(self):
        f = _sample_finding(tool=None)
        rule = ks.rule_for(f)
        # tool defaults to "sec-audit"
        assert "sec-audit" in rule["properties"]["tags"]


# ===========================================================================
# 2. result_for()
# ===========================================================================

class TestResultFor:
    def test_rule_id(self):
        result = ks.result_for(_sample_finding(), rule_index=0)
        assert result["ruleId"] == "sec-sast-deep/idor"

    def test_rule_index(self):
        result = ks.result_for(_sample_finding(), rule_index=3)
        assert result["ruleIndex"] == 3

    def test_level_maps_severity(self):
        result = ks.result_for(_sample_finding(severity="critical"), rule_index=0)
        assert result["level"] == "error"

    def test_message_includes_finding_text(self):
        result = ks.result_for(_sample_finding(), rule_index=0)
        assert "IDOR on /api/users/{id}" in result["message"]["text"]

    def test_message_includes_source(self):
        result = ks.result_for(_sample_finding(), rule_index=0)
        assert "Untrusted source: user_id from query param." in result["message"]["text"]

    def test_message_includes_confidence(self):
        result = ks.result_for(_sample_finding(confidence=0.85), rule_index=0)
        assert "Confidence: 0.85." in result["message"]["text"]

    def test_message_includes_decision(self):
        result = ks.result_for(_sample_finding(decision="real"), rule_index=0)
        assert "Decision: real." in result["message"]["text"]

    def test_no_source_skips_source_line(self):
        f = _sample_finding(evidence={})
        result = ks.result_for(f, rule_index=0)
        assert "Untrusted source" not in result["message"]["text"]

    def test_no_confidence_skips_confidence_line(self):
        f = _sample_finding(confidence=None)
        result = ks.result_for(f, rule_index=0)
        assert "Confidence" not in result["message"]["text"]

    def test_suppressed_has_suppressions(self):
        f = _sample_finding(decision="suppressed", evidence={"note": "acknowledged risk"})
        result = ks.result_for(f, rule_index=0)
        assert "suppressions" in result
        assert len(result["suppressions"]) == 1
        assert result["suppressions"][0]["kind"] == "external"
        assert result["suppressions"][0]["justification"] == "acknowledged risk"

    def test_suppressed_default_justification(self):
        f = _sample_finding(decision="suppressed", evidence={})
        result = ks.result_for(f, rule_index=0)
        assert "suppressions" in result
        assert "suppressed by the kit" in result["suppressions"][0]["justification"]

    def test_non_suppressed_no_suppressions_key(self):
        f = _sample_finding(decision="real")
        result = ks.result_for(f, rule_index=0)
        assert "suppressions" not in result

    def test_undecided_no_suppressions_key(self):
        f = _sample_finding(decision=None)
        result = ks.result_for(f, rule_index=0)
        assert "suppressions" not in result

    def test_fingerprint_matches_finding_id(self):
        f = _sample_finding(id="sak-042")
        result = ks.result_for(f, rule_index=0)
        assert result["partialFingerprints"]["sakFindingId"] == "sak-042"

    def test_location_uri(self):
        f = _sample_finding(file="src/handler.py")
        result = ks.result_for(f, rule_index=0)
        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "src/handler.py"

    def test_location_region_line(self):
        f = _sample_finding(line=99)
        result = ks.result_for(f, rule_index=0)
        loc = result["locations"][0]["physicalLocation"]
        assert loc["region"]["startLine"] == 99

    def test_location_no_region_when_no_line(self):
        f = _sample_finding(line=None)
        result = ks.result_for(f, rule_index=0)
        loc = result["locations"][0]["physicalLocation"]
        assert "region" not in loc


# ===========================================================================
# 3. main() — end-to-end
# ===========================================================================

class TestMain:
    def _write_evidence(self, tmp_path, doc):
        ev = tmp_path / "evidence.json"
        ev.write_text(json.dumps(doc), encoding="utf-8")
        return ev

    def test_writes_sarif_with_judgment_findings(self, tmp_path, monkeypatch):
        finding = _sample_finding()
        doc = _minimal_evidence(findings=[finding])
        ev = self._write_evidence(tmp_path, doc)
        out = tmp_path / "kit.sarif"

        monkeypatch.setattr(
            "sys.argv",
            ["kit_sarif.py", "--evidence", str(ev), "--out", str(out)],
        )
        rc = ks.main()
        assert rc == 0
        assert out.exists()

        sarif = json.loads(out.read_text(encoding="utf-8"))
        assert sarif["version"] == "2.1.0"
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "SecurityAuditKit"
        assert len(run["results"]) == 1
        assert run["results"][0]["ruleId"] == "sec-sast-deep/idor"
        # Rules are deduplicated and referenced
        assert len(run["tool"]["driver"]["rules"]) == 1

    def test_no_judgment_findings_returns_zero_no_file(self, tmp_path, monkeypatch):
        # Finding without dimension="judgment" should be ignored
        scanner_finding = _sample_finding(dimension="scanner")
        doc = _minimal_evidence(findings=[scanner_finding])
        ev = self._write_evidence(tmp_path, doc)
        out = tmp_path / "kit.sarif"

        monkeypatch.setattr(
            "sys.argv",
            ["kit_sarif.py", "--evidence", str(ev), "--out", str(out)],
        )
        rc = ks.main()
        assert rc == 0
        assert not out.exists()

    def test_empty_findings_returns_zero_no_file(self, tmp_path, monkeypatch):
        doc = _minimal_evidence(findings=[])
        ev = self._write_evidence(tmp_path, doc)
        out = tmp_path / "kit.sarif"

        monkeypatch.setattr(
            "sys.argv",
            ["kit_sarif.py", "--evidence", str(ev), "--out", str(out)],
        )
        rc = ks.main()
        assert rc == 0
        assert not out.exists()

    def test_missing_evidence_returns_zero(self, tmp_path, monkeypatch):
        ev = tmp_path / "nonexistent.json"
        out = tmp_path / "kit.sarif"

        monkeypatch.setattr(
            "sys.argv",
            ["kit_sarif.py", "--evidence", str(ev), "--out", str(out)],
        )
        rc = ks.main()
        assert rc == 0
        assert not out.exists()

    def test_invalid_schema_returns_one(self, tmp_path, monkeypatch):
        doc = {"schema": "something/else@2", "findings": []}
        ev = self._write_evidence(tmp_path, doc)
        out = tmp_path / "kit.sarif"

        monkeypatch.setattr(
            "sys.argv",
            ["kit_sarif.py", "--evidence", str(ev), "--out", str(out)],
        )
        rc = ks.main()
        assert rc == 1
        assert not out.exists()

    def test_invalid_json_returns_one(self, tmp_path, monkeypatch):
        ev = tmp_path / "evidence.json"
        ev.write_text("not json at all", encoding="utf-8")
        out = tmp_path / "kit.sarif"

        monkeypatch.setattr(
            "sys.argv",
            ["kit_sarif.py", "--evidence", str(ev), "--out", str(out)],
        )
        rc = ks.main()
        assert rc == 1

    def test_suppressed_finding_in_sarif(self, tmp_path, monkeypatch):
        f = _sample_finding(decision="suppressed", evidence={"note": "accepted risk"})
        doc = _minimal_evidence(findings=[f])
        ev = self._write_evidence(tmp_path, doc)
        out = tmp_path / "kit.sarif"

        monkeypatch.setattr(
            "sys.argv",
            ["kit_sarif.py", "--evidence", str(ev), "--out", str(out)],
        )
        rc = ks.main()
        assert rc == 0

        sarif = json.loads(out.read_text(encoding="utf-8"))
        result = sarif["runs"][0]["results"][0]
        assert "suppressions" in result
        assert result["suppressions"][0]["justification"] == "accepted risk"

    def test_multiple_findings_dedup_rules(self, tmp_path, monkeypatch):
        f1 = _sample_finding(id="sak-001", rule_id="sec-sast-deep/idor")
        f2 = _sample_finding(id="sak-002", rule_id="sec-sast-deep/idor", file="src/other.py", line=10)
        f3 = _sample_finding(id="sak-003", rule_id="sec-ai-review/prompt-injection", tool="sec-ai-review")
        doc = _minimal_evidence(findings=[f1, f2, f3])
        ev = self._write_evidence(tmp_path, doc)
        out = tmp_path / "kit.sarif"

        monkeypatch.setattr(
            "sys.argv",
            ["kit_sarif.py", "--evidence", str(ev), "--out", str(out)],
        )
        rc = ks.main()
        assert rc == 0

        sarif = json.loads(out.read_text(encoding="utf-8"))
        run = sarif["runs"][0]
        assert len(run["results"]) == 3
        # Two unique rules, not three
        assert len(run["tool"]["driver"]["rules"]) == 2
