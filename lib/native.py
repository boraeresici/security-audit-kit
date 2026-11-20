#!/usr/bin/env python3
"""Adapters for tools that write their own JSON instead of SARIF (F16b).

Each adapter turns one tool's native output into the kit's finding rows, keeping what SARIF would
lose (package, version, aliases, fixes). The rows go to evidence.json and the HTML report; they are
not SARIF, so a CI job that uploads sarif/*.sarif does not send them to Code Scanning. Stdlib only.

Usage (scan.sh): native.py summary <tool> <file>   -> a few readable lines for the scan log
"""
from __future__ import annotations

import hashlib
import json
import sys

# native output file (in the run's sarif/ directory) -> (tool, scan.sh dimension)
NATIVE_SOURCES = {
    "pip-audit.native.json": ("pip-audit", "py-deps"),
    "checkov.native.json": ("checkov", "iac"),
}


def _id(dimension: str, rule_id: str, key: str) -> str:
    # A dependency finding has no file:line; the package is what makes two advisories two findings.
    return hashlib.sha1(f"{dimension}|{rule_id}|{key}|".encode("utf-8")).hexdigest()[:12]


def parse_pip_audit(doc, warnings: list) -> list:
    """pip-audit `--format json` -> finding rows. pip-audit gives no severity: `unknown`, never a guess."""
    if not isinstance(doc, dict) or not isinstance(doc.get("dependencies"), list):
        warnings.append("pip-audit.native.json: not pip-audit JSON (no dependencies list) -> no rows")
        return []
    out = []
    for dep in doc["dependencies"]:
        if not isinstance(dep, dict):
            continue
        name, version = str(dep.get("name") or "?"), str(dep.get("version") or "")
        if dep.get("skip_reason"):
            warnings.append(f"pip-audit: {name} not audited ({' '.join(str(dep['skip_reason']).split())[:200]})")
            continue
        seen = set()
        for v in dep.get("vulns") or []:
            vid = str((v or {}).get("id") or "")
            if not vid or vid in seen:      # pip-audit can list one advisory twice for a package
                continue
            seen.add(vid)
            fixes = [str(x) for x in v.get("fix_versions") or []]
            aliases = sorted({str(a) for a in v.get("aliases") or []} - {vid})
            out.append({
                "id": _id("py-deps", vid, f"pypi:{name.lower()}"),
                "dimension": "py-deps",
                "tool": "pip-audit",
                "rule_id": vid,
                "file": None,
                "line": None,
                "message": f"{name} {version}: {vid}" + (f", fixed in {', '.join(fixes)}" if fixes else ", no fixed version"),
                "severity": "unknown",
                "severity_source": "pip-audit:none",
                "cvss": None,
                "decision": None,
                "confidence": None,
                "evidence": None,
                "package": {"ecosystem": "pypi", "name": name, "version": version},
                "aliases": aliases,
                "fixed_in": fixes,
            })
    return out


def parse_checkov(doc, warnings: list) -> list:
    """checkov `-o json` -> rows. One object per framework, or a list of them. checkov gives no severity
    without a platform key: `unknown`. A `#checkov:skip=` check is kept as suppressed, with its reason."""
    docs = doc if isinstance(doc, list) else [doc]
    if not docs or not all(isinstance(d, dict) and isinstance(d.get("results"), dict) for d in docs):
        warnings.append("checkov.native.json: not checkov JSON (no results) -> no rows")
        return []
    out = []
    for d in docs:
        res = d["results"]
        for kind in ("failed_checks", "skipped_checks"):
            for c in res.get(kind) or []:
                if not isinstance(c, dict) or not c.get("check_id"):
                    continue
                path = str(c.get("repo_file_path") or c.get("file_path") or "").lstrip("/") or None
                lines = c.get("file_line_range") or [None]
                line = lines[0] if isinstance(lines[0], int) and lines[0] > 0 else None
                resource = str(c.get("resource") or "")
                skipped = kind == "skipped_checks"
                why = " ".join(str((c.get("check_result") or {}).get("suppress_comment") or "").split())
                sev = str(c.get("severity") or "").lower()
                out.append({
                    "id": _id("iac", c["check_id"], f"{path}|{resource}"),
                    "dimension": "iac",
                    "tool": "checkov",
                    "rule_id": c["check_id"],
                    "file": path,
                    "line": line,
                    "message": f"{resource}: {c.get('check_name') or c['check_id']}",
                    "severity": sev if sev in ("critical", "high", "medium", "low") else "unknown",
                    "severity_source": f"checkov:{sev or 'none'}",
                    "cvss": None,
                    "decision": "suppressed" if skipped else None,
                    "confidence": None,
                    "evidence": ({"sink": f"{path}:{line}" if line else path, "source": None,
                                  "note": "suppressed in source (#checkov:skip)" + (f": {why}" if why else "")}
                                 if skipped else None),
                    "resource": resource,
                    "guideline": c.get("guideline"),
                })
        for e in res.get("parsing_errors") or []:
            warnings.append(f"checkov could not parse {str(e)[:200]} -> not checked")
    return out


PARSERS = {"pip-audit": parse_pip_audit, "checkov": parse_checkov}


def summary(tool: str, path: str) -> int:
    """Readable lines for the scan log: the JSON goes to a file, so the tool's own table is gone."""
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"{tool}: output unreadable ({exc.__class__.__name__})")
        return 2
    if not isinstance(doc, dict) or not isinstance(doc.get("dependencies"), list):
        print(f"{tool}: output is not {tool} JSON")
        return 2
    warnings: list = []
    rows = PARSERS[tool](doc, warnings)
    listed = sum(len(d.get("vulns") or []) for d in doc.get("dependencies") or [] if isinstance(d, dict)) \
        if isinstance(doc, dict) else 0
    for r in rows:
        print(f"  {r['message']}" + (f"  (aka {', '.join(r['aliases'])})" if r["aliases"] else ""))
    for w in warnings:
        print(f"  ! {w}")
    dup = f" (pip-audit listed {listed} entries; it repeats advisories)" if listed > len(rows) else ""
    print(f"{tool}: {len(rows)} known vulnerabilit{'y' if len(rows) == 1 else 'ies'}"
          f" in {len({r['package']['name'] for r in rows})} package(s){dup}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "summary" and sys.argv[2] == "pip-audit":
        sys.exit(summary(sys.argv[2], sys.argv[3]))
    print("usage: native.py summary pip-audit <file>", file=sys.stderr)
    sys.exit(2)
