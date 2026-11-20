"""Facts recorded from the pinned scanners (tests/fixtures/native/*/README.md).

These tests read recorded output, not a live tool: they fail when a fixture is re-recorded after a
pin bump and the behaviour changed, which is the moment the kit's assumptions must be revisited.
"""
from __future__ import annotations

import json
import os

HERE = os.path.join(os.path.dirname(__file__), "..", "fixtures", "native", "uvlock")


def _load(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as fh:
        return json.load(fh)


def _trivy_ids(doc):
    return {v["VulnerabilityID"] for r in doc.get("Results") or [] for v in r.get("Vulnerabilities") or []}


class TestUvLock:
    def test_pinned_trivy_does_not_read_uv_lock(self):
        assert not _load("trivy-0.58.0-uvlock.json").get("Results")

    def test_pinned_trivy_reads_the_same_pin_from_requirements(self):
        assert "CVE-2021-33503" in _trivy_ids(_load("trivy-0.58.0-requirements.json"))

    def test_osv_reads_uv_lock_and_names_the_advisory_by_its_pysec_id(self):
        doc = _load("osv-v2.4.0-uvlock.json")
        vulns = [v for r in doc["results"] for p in r["packages"] for v in p["vulnerabilities"]]
        hit = [v for v in vulns if v["id"] == "PYSEC-2021-108"]
        assert hit and {"CVE-2021-33503", "GHSA-q2q7-5pp4-w6pg"} <= set(hit[0]["aliases"])

    def test_pip_audit_names_it_by_the_pysec_id_too(self):
        deps = _load("pip-audit-2.10.1-exported.json")["dependencies"]
        ids = {v["id"] for d in deps for v in d.get("vulns", [])}
        assert "PYSEC-2021-108" in ids and "CVE-2021-33503" not in ids
