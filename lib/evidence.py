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


# --- judgment layer: the findings file the skills write ------------------------------------
# The skills write ONE artifact a human reads (findings-<date>.md). Rather than ask a model to also
# emit JSON — two sources of truth that drift — we parse that file. Tables are read by their HEADER
# NAMES, not by column position, so each skill keeps the table shape that suits it and a reordered
# or extra column changes nothing here. A row we cannot parse is skipped with a warning, never
# guessed at.
SEVERITY_WORDS = {
    "critical": "critical", "crit": "critical", "blocker": "critical",
    "high": "high", "error": "high", "major": "high",
    "medium": "medium", "med": "medium", "warning": "medium", "moderate": "medium",
    "low": "low", "note": "low", "minor": "low",
    "info": "info", "informational": "info", "none": "info",
}
DECISION_WORDS = {
    "real": "real", "confirmed": "real", "true": "real", "true-positive": "real",
    "fp": "fp", "false-positive": "fp", "false positive": "fp",
    "uncertain": "uncertain", "unsure": "uncertain",
    "suppressed": "suppressed",
}
SKILL_NAMES = ("sec-triage", "sec-sast-deep", "sec-ai-review", "sec-threat-model", "sec-audit")


def column_role(name: str):
    """Map a table header cell to the field it carries. Unknown headers are simply ignored."""
    n = name.strip().lower()
    if "sink" in n or "location" in n or n == "where":
        return "loc"
    if n.startswith("tool"):
        return "tool"
    if "source" in n:
        return "source"
    if n.startswith("sev"):
        return "sev"
    if n.startswith("conf"):
        return "conf"
    if "decision" in n or "verdict" in n:
        return "decision"
    if "action" in n or "fix" in n:
        return "action"
    if n.startswith("why") or "reason" in n:
        return "why"
    if "class" in n or "owasp" in n or "rule" in n or n == "id":
        return "cls"
    return None


def split_row(line: str) -> list:
    cells = line.strip().strip("|").split("|")
    return [c.strip() for c in cells]


def is_separator(line: str) -> bool:
    body = line.strip().strip("|").replace(":", "").replace("-", "").replace("|", "")
    return line.strip().startswith("|") and "-" in line and body.strip() == ""


def parse_location(text: str):
    """'path/to/x.py:88' -> ('path/to/x.py', 88). Backticks and stray markdown are tolerated."""
    raw = text.strip().strip("`").strip()
    if not raw or raw in {"-", "—", "n/a"}:
        return None, None
    if ":" in raw:
        head, _, tail = raw.rpartition(":")
        if head and tail.isdigit():
            return head.strip(), int(tail)
    return raw, None


def slug(text: str, fallback: str) -> str:
    keep = [c.lower() if c.isalnum() else "-" for c in text.strip()]
    out = "".join(keep).strip("-")
    while "--" in out:
        out = out.replace("--", "-")
    return out[:48] or fallback


def parse_findings_md(path: str, warnings: list) -> list:
    """-> judgment findings: [{origin, tool, rule_id, file, line, severity, decision, ...}]."""
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except FileNotFoundError:
        return []
    except OSError as exc:
        warnings.append(f"findings file unreadable ({exc.__class__.__name__}) -> judgment layer skipped")
        return []

    origin = "sec-triage"
    suppressed_section = False
    skip_section = False
    header = None
    out = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#"):
            header = None
            low = stripped.lower()
            named = [s for s in SKILL_NAMES if s in low]
            if named:
                origin = named[0]
            # "Kit issues" reports bugs in the kit itself, not findings about this repo.
            skip_section = "kit issue" in low
            suppressed_section = "suppressed" in low
            continue
        if not stripped.startswith("|") or skip_section:
            continue
        if is_separator(stripped):
            continue
        cells = split_row(stripped)
        if header is None:
            roles = [column_role(c) for c in cells]
            header = roles if any(r in ("loc", "decision") for r in roles) else []
            continue
        if not header:
            continue
        row = {}
        for role, value in zip(header, cells):
            if role:
                row[role] = value
        path_, line_no = parse_location(row.get("loc", ""))
        if not path_:
            continue

        sev_raw = row.get("sev", "").strip()
        severity = SEVERITY_WORDS.get(sev_raw.lower())
        if severity is None:
            if sev_raw:
                warnings.append(f"findings file: unmapped severity {sev_raw!r} at {path_} -> info")
            severity = "info"

        decision_raw = row.get("decision", "").strip().lower()
        decision = "suppressed" if suppressed_section else DECISION_WORDS.get(decision_raw)
        if decision is None:
            decision = "uncertain" if decision_raw else None

        confidence = None
        try:
            confidence = float(row.get("conf", "").strip())
        except ValueError:
            pass

        tool = row.get("tool", "").strip() or origin
        cls = row.get("cls", "").strip()
        # Rule id names what the finding IS: its class when the table gives one (deep passes), else
        # the tool that raised it (triage rows), else a generic id. Never a row number — the id has
        # to stay stable across scans so an alert is not recreated every run.
        kind = cls or (tool if tool != origin else "") or "finding"
        out.append({
            "origin": origin,
            "tool": tool,
            "rule_id": f"SAK-{origin.replace('sec-', '')}-{slug(kind, 'finding')}",
            "file": path_,
            "line": line_no,
            "message": (row.get("action") or row.get("why") or cls or "judgment finding").strip(),
            "severity": severity,
            "severity_source": f"{origin}:{sev_raw or 'none'}",
            "decision": decision,
            "confidence": confidence,
            "evidence": {
                "sink": f"{path_}:{line_no}" if line_no else path_,
                "source": row.get("source", "").strip() or None,
                "note": (row.get("action") or row.get("why") or "").strip() or None,
            },
        })
    return out


def merge_judgment(findings: list, judged: list, warnings: list) -> list:
    """Attach decisions to the scanner findings they refer to; keep the rest as their own entries.

    A triage row about a semgrep hit is the SAME finding the scanner reported, so it must not become
    a second entry — it fills in decision/confidence/evidence. A deep-pass finding has no scanner
    counterpart and becomes a new `judgment` finding, which is exactly what kit.sarif reports.
    """
    by_location = {}
    for f in findings:
        by_location.setdefault((f["file"], f["line"]), []).append(f)

    for j in judged:
        candidates = by_location.get((j["file"], j["line"]), [])
        match = None
        for c in candidates:
            if c["tool"].startswith(j["tool"].split("-")[0]) or j["tool"] in c["tool"]:
                match = c
                break
        if match is None and len(candidates) == 1 and j["origin"] == "sec-triage":
            match = candidates[0]
        if match is not None:
            match["decision"] = j["decision"]
            match["confidence"] = j["confidence"]
            match["evidence"] = j["evidence"]
            continue
        findings.append({
            "id": finding_id("judgment", j["rule_id"], j["file"] or "", j["line"]),
            "dimension": "judgment",
            "tool": j["origin"],
            "rule_id": j["rule_id"],
            "file": j["file"],
            "line": j["line"],
            "message": j["message"],
            "severity": j["severity"],
            "severity_source": j["severity_source"],
            "cvss": None,      # a judgment finding never carries a score we did not measure
            "decision": j["decision"],
            "confidence": j["confidence"],
            "evidence": j["evidence"],
        })
    return findings


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
    ap.add_argument("--findings", help="findings-<date>.md written by the judgment skills (optional)")
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

    if args.findings:
        judged = parse_findings_md(args.findings, warnings)
        if judged:
            findings = merge_judgment(findings, judged, warnings)

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
    by_decision = {"real": 0, "fp": 0, "uncertain": 0, "suppressed": 0, "undecided": 0}
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
