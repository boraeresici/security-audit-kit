#!/usr/bin/env python3
"""Render the JUDGMENT findings in evidence.json as SARIF 2.1.0 (`kit.sarif`).

Why this exists: the scanners already upload their own SARIF, but the skills' findings — an IDOR
`sec-sast-deep` traced through the call path, a prompt-injection sink `sec-ai-review` found — live
only in `findings-<date>.md` and never reach Code Scanning. This puts them where the scanner
findings already are, on the same review surface.

What it does NOT do: re-report scanner findings. A semgrep hit is already in `semgrep.sarif`;
emitting it again under a kit rule id would double every alert. Triage decisions about scanner
findings are recorded in `evidence.json` (and rendered by the HTML report) instead.

Suppression caveat: SARIF `suppressions` dismiss results **within this run**. A finding the triage
suppressed is emitted here as a suppressed result — on record, not silently absent — but that
cannot dismiss another tool's alert from another run; GitHub scopes suppression per run.

Stdlib only, deterministic output (sorted, no timestamps).

Usage:  kit_sarif.py --evidence <evidence.json> --out <kit.sarif>
"""
from __future__ import annotations

import argparse
import json
import sys

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
DRIVER_NAME = "SecurityAuditKit"
INFO_URI = "https://github.com/boraeresici/security-audit-kit"

# Our buckets -> SARIF levels. We deliberately do NOT emit `security-severity`: that number is read
# as a CVSS score, and a judgment finding has no measured score. Level carries the ranking.
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "none"}

SKILL_DESCRIPTION = {
    "sec-triage": "Triage judgment over scanner output",
    "sec-sast-deep": "Semantic SAST: authorization, IDOR, business logic, stack-specific injection",
    "sec-ai-review": "AI/LLM application review (OWASP LLM Top 10)",
    "sec-threat-model": "STRIDE / data-flow threat modeling",
    "sec-audit": "Consolidated audit orchestration",
}


def rule_for(finding: dict) -> dict:
    tool = finding.get("tool") or "sec-audit"
    return {
        "id": finding["rule_id"],
        "name": finding["rule_id"].replace("-", ""),
        "shortDescription": {"text": SKILL_DESCRIPTION.get(tool, "security-audit-kit judgment finding")},
        "fullDescription": {"text": (
            f"Reported by the {tool} skill. Judgment finding: a human-reviewable claim with a sink, "
            "an untrusted source and a confidence score — not a pattern match."
        )},
        "defaultConfiguration": {"level": LEVEL.get(finding.get("severity"), "warning")},
        "properties": {"tags": ["security", "security-audit-kit", tool]},
        "helpUri": INFO_URI,
    }


def result_for(finding: dict, rule_index: int) -> dict:
    evidence = finding.get("evidence") or {}
    bits = [finding.get("message") or "judgment finding"]
    if evidence.get("source"):
        bits.append(f"Untrusted source: {evidence['source']}.")
    if finding.get("confidence") is not None:
        bits.append(f"Confidence: {finding['confidence']}.")
    if finding.get("decision"):
        bits.append(f"Decision: {finding['decision']}.")

    result = {
        "ruleId": finding["rule_id"],
        "ruleIndex": rule_index,
        "level": LEVEL.get(finding.get("severity"), "warning"),
        "message": {"text": " ".join(bits)},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": finding.get("file") or "", "uriBaseId": "%SRCROOT%"},
                **({"region": {"startLine": finding["line"]}} if finding.get("line") else {}),
            }
        }],
        # Stable across runs, so an alert is not re-created every scan.
        "partialFingerprints": {"sakFindingId": finding["id"]},
    }
    if finding.get("decision") == "suppressed":
        result["suppressions"] = [{
            "kind": "external",
            "justification": (evidence.get("note") or "suppressed by the kit's triage gates"),
        }]
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description="Render judgment findings as SARIF 2.1.0")
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    try:
        with open(args.evidence, encoding="utf-8") as fh:
            document = json.load(fh)
    except FileNotFoundError:
        print(f"[scan:kit-sarif] no evidence.json at {args.evidence} -> nothing to emit")
        return 0
    except ValueError as exc:
        print(f"[scan:kit-sarif] evidence.json is not valid JSON ({exc}) -> nothing emitted", file=sys.stderr)
        return 1

    schema = document.get("schema", "")
    if not schema.startswith("security-audit-kit/evidence@1"):
        print(f"[scan:kit-sarif] unsupported evidence schema {schema!r} -> refusing to guess", file=sys.stderr)
        return 1

    judgment = [f for f in document.get("findings", []) if f.get("dimension") == "judgment"]
    judgment.sort(key=lambda f: (f.get("file") or "", f.get("line") or 0, f["rule_id"], f["id"]))

    # An empty run is a CLAIM: uploaded to Code Scanning it closes every open kit alert. But no
    # judgment findings usually means no judgment pass ran this time, not that the findings are
    # gone — so we refuse to assert it, and leave any previous kit.sarif in place.
    if not judgment:
        print("[scan:kit-sarif] no judgment findings (run /sec-triage or a deep pass first) -> kit.sarif left unchanged")
        return 0

    rules, rule_index = [], {}
    for f in judgment:
        if f["rule_id"] not in rule_index:
            rule_index[f["rule_id"]] = len(rules)
            rules.append(rule_for(f))

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": DRIVER_NAME,
                "informationUri": INFO_URI,
                "rules": rules,
            }},
            "results": [result_for(f, rule_index[f["rule_id"]]) for f in judgment],
        }],
    }

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2)
        fh.write("\n")
    suppressed = sum(1 for f in judgment if f.get("decision") == "suppressed")
    print(f"[scan:kit-sarif] wrote {args.out} ({len(judgment)} judgment findings, {suppressed} suppressed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
