#!/usr/bin/env python3
"""Build evidence.json — the kit's normalized, per-finding record — from SARIF + summary.json.

Contract and severity mapping tables: docs/schema/evidence.md (that file is the spec; this is the
implementation of it). Stdlib only, deterministic output, no network.

Usage:
  evidence.py --sarif-dir <dir> --summary <summary.json> --out <evidence.json>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

SCHEMA = "security-audit-kit/evidence@1"

# SARIF file -> (tool name, scan.sh dimension). The dimension is what lets us include only the
# findings this run actually produced: the sarif/ directory persists between scans.
SARIF_SOURCES = {
    "gitleaks.sarif": ("gitleaks", "secret"),
    "semgrep.sarif": ("semgrep", "sast"),
    "trivy.sarif": ("trivy", "container"),
    "osv.sarif": ("osv-scanner", "osv"),
    "zizmor.sarif": ("zizmor", "zizmor"),
}

# A dimension alias runs the same tool over a different scope, so its SARIF is the same file.
DIMENSION_ALIASES = {"staged": "secret", "changed": "sast"}

# Tool default when the SARIF carries neither a numeric score nor a usable level.
TOOL_DEFAULT = {
    "gitleaks": "high",      # a committed credential is not a "warning"
    "semgrep": "medium",
    "trivy": "medium",
    "osv-scanner": "medium",
    "zizmor": "medium",
}

# Tools whose security-severity IS derived from a real CVSS score, so it may be passed through.
CVSS_TOOLS = {"trivy", "osv-scanner"}

LEVEL_TO_SEVERITY = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
SEVERITIES = ("critical", "high", "medium", "low", "info")


def band(score: float) -> str:
    """CVSS bands, GitHub's security-severity convention."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def rule_index(run: dict) -> dict:
    """rule id -> rule object, across driver and extensions (tools differ in where they put them)."""
    index = {}
    tool = run.get("tool") or {}
    components = [tool.get("driver") or {}]
    components.extend(tool.get("extensions") or [])
    for component in components:
        for rule in component.get("rules") or []:
            rid = rule.get("id")
            if rid:
                index.setdefault(rid, rule)
    return index


def numeric_severity(rule: dict):
    """The rule's security-severity as a float, or None when absent/unparseable."""
    raw = (rule.get("properties") or {}).get("security-severity")
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def classify(tool: str, result: dict, rule: dict, warnings: list, where: str):
    """-> (severity, severity_source, cvss). Never raises, never drops: unknown becomes info."""
    score = numeric_severity(rule)
    if score is not None:
        cvss = score if tool in CVSS_TOOLS else None
        return band(score), f"{tool}:security-severity={score:g}", cvss

    level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level")
    if level:
        mapped = LEVEL_TO_SEVERITY.get(str(level).lower())
        if mapped:
            return mapped, f"{tool}:level={str(level).lower()}", None
        warnings.append(f"{where}: unmapped SARIF level {level!r} -> info")
        return "info", f"{tool}:level={level}", None

    default = TOOL_DEFAULT.get(tool)
    if default:
        return default, f"{tool}:none", None
    warnings.append(f"{where}: no severity signal and no tool default -> info")
    return "info", f"{tool}:none", None


# The docker-run tools see the repo mounted at /repo, so their SARIF carries container paths
# (file:///repo/requirements.txt). Paths in evidence.json are repo-relative — the mount is our
# implementation detail and must not leak into the record a report or SARIF upload renders.
CONTAINER_MOUNT = "/repo/"


def location_of(result: dict):
    """-> (file, line). Missing locations are legal SARIF; report them as (None, None)."""
    for loc in result.get("locations") or []:
        physical = loc.get("physicalLocation") or {}
        uri = (physical.get("artifactLocation") or {}).get("uri")
        line = (physical.get("region") or {}).get("startLine")
        if uri:
            if uri.startswith("file://"):
                uri = uri[len("file://"):]
            if uri.startswith(CONTAINER_MOUNT):
                uri = uri[len(CONTAINER_MOUNT):]
            return uri.lstrip("/"), (int(line) if isinstance(line, int) else None)
    return None, None


def message_of(result: dict) -> str:
    text = (result.get("message") or {}).get("text") or ""
    return " ".join(text.split())


def finding_id(dimension: str, rule_id: str, path: str, line) -> str:
    key = f"{dimension}|{rule_id}|{path}|{line if line is not None else ''}"
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]


def read_json(path: str, warnings: list, label: str):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        warnings.append(f"{label}: unreadable ({exc.__class__.__name__}) -> skipped")
        return None


def collect(sarif_path: str, tool: str, dimension: str, warnings: list) -> list:
    doc = read_json(sarif_path, warnings, os.path.basename(sarif_path))
    if not doc:
        return []
    findings = []
    for run in doc.get("runs") or []:
        rules = rule_index(run)
        for result in run.get("results") or []:
            rule_id = result.get("ruleId") or (result.get("rule") or {}).get("id") or "(none)"
            path, line = location_of(result)
            where = f"{os.path.basename(sarif_path)}:{rule_id}"
            severity, source, cvss = classify(tool, result, rules.get(rule_id, {}), warnings, where)
            findings.append({
                "id": finding_id(dimension, rule_id, path or "", line),
                "dimension": dimension,
                "tool": tool,
                "rule_id": rule_id,
                "file": path,
                "line": line,
                "message": message_of(result),
                "severity": severity,
                "severity_source": source,
                "cvss": cvss,
                "decision": None,
                "confidence": None,
                "evidence": None,
            })
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description="Build evidence.json from SARIF + summary.json")
    ap.add_argument("--sarif-dir", required=True)
    ap.add_argument("--summary", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    warnings: list = []
    summary = read_json(args.summary, warnings, "summary.json") or {}
    dimensions = summary.get("dimensions") or []

    if dimensions:
        ran = {DIMENSION_ALIASES.get(d.get("name"), d.get("name")) for d in dimensions}
    else:
        # No summary to scope by: take whatever SARIF is on disk, but say so — some of it may be
        # left over from an earlier scan of a different scope.
        ran = {dim for _, dim in SARIF_SOURCES.values()}
        warnings.append("no summary.json dimensions -> included every SARIF file on disk, which may be stale")

    findings: list = []
    for filename, (tool, dimension) in sorted(SARIF_SOURCES.items()):
        if dimension not in ran:
            continue
        path = os.path.join(args.sarif_dir, filename)
        if os.path.exists(path):
            findings.extend(collect(path, tool, dimension, warnings))

    # Deduplicate by identity. osv-scanner, for one, emits the same advisory once per affected
    # package version, which would triple-count a single CVE in one manifest line. Same id = same
    # (dimension, rule, file, line) = one finding to a human, so keep the first and drop the rest.
    unique = {}
    duplicates = 0
    for f in findings:
        if f["id"] in unique:
            duplicates += 1
            continue
        unique[f["id"]] = f
    if duplicates:
        warnings.append(f"dropped {duplicates} duplicate result(s) reported by a tool for the same rule+location")
    findings = list(unique.values())

    findings.sort(key=lambda f: (f["dimension"], f["file"] or "", f["line"] or 0, f["rule_id"], f["id"]))

    by_severity = {s: 0 for s in SEVERITIES}
    for f in findings:
        by_severity[f["severity"]] += 1
    by_decision = {"real": 0, "fp": 0, "suppressed": 0, "undecided": 0}
    for f in findings:
        by_decision[f["decision"] or "undecided"] += 1

    document = {
        "schema": SCHEMA,
        # No timestamp on purpose: two runs over unchanged code must diff to nothing.
        "scan": {
            "command": summary.get("command"),
            "exit_code": summary.get("exit_code"),
            "raw_log": summary.get("raw_log"),
            "dimensions": dimensions,
        },
        "counts": {"total": len(findings), "by_severity": by_severity, "by_decision": by_decision},
        "findings": findings,
        "warnings": warnings,
    }

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2, sort_keys=False)
        fh.write("\n")
    print(f"[scan:evidence] wrote {args.out} ({len(findings)} findings, {len(warnings)} warnings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
