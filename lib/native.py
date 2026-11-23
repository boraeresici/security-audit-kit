#!/usr/bin/env python3
"""Adapters for tools that write their own JSON instead of SARIF (F16b).

Each adapter turns one tool's native output into the kit's finding rows, keeping what SARIF would
lose (package, version, aliases, fixes). The rows go to evidence.json and the HTML report; they are
not SARIF, so a CI job that uploads sarif/*.sarif does not send them to Code Scanning. Stdlib only.

Usage (scan.sh): native.py summary pip-audit <file>   -> a few readable lines for the scan log
                 native.py guarddog-add <pypi|npm> <manifest> <verify.json> <record.json>
                 native.py guarddog-gate <record.json> [block-extra] [report-extra]
                 native.py npm-add <dir> <audit.json> <record.json>
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys

# native output file (in the run's sarif/ directory) -> (tool, scan.sh dimension)
NATIVE_SOURCES = {
    "pip-audit.native.json": ("pip-audit", "py-deps"),
    "checkov.native.json": ("checkov", "iac"),
    "guarddog.native.json": ("guarddog", "guarddog"),
    "npm-audit.native.json": ("npm-audit", "js-deps"),
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


def _pypi_name(n: str) -> str:
    return re.sub(r"[-_.]+", "-", n).lower()          # PEP 503


def requested_packages(ecosystem: str, manifest: str) -> list:
    """The packages a manifest asks for, as guarddog `verify` reads them: every requirement line for
    pypi; dependencies and devDependencies for npm (measured, guarddog 3.0.2, both are verified)."""
    try:
        text = open(manifest, encoding="utf-8").read()
    except (OSError, UnicodeDecodeError):
        return []
    if ecosystem == "npm":
        try:
            doc = json.loads(text)
        except ValueError:
            return []
        names = set()
        for key in ("dependencies", "devDependencies"):
            if isinstance(doc.get(key), dict):
                names.update(str(k).lower() for k in doc[key])
        return sorted(names)
    names = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        m = re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*", line)
        if line and not line.startswith("-") and m:
            names.add(_pypi_name(m.group(0)))
    return sorted(names)


def parse_guarddog(doc, warnings: list) -> list:
    """The kit's guarddog record -> rows: one per package and fired rule that is not a capability-*
    rule (capabilities say what a package CAN do; requests fires three). The severity is guarddog's
    own, from `risks`, where it gives one; a package it was asked about and returned nothing for is
    named as not checked, never counted as clean (guarddog drops a package it cannot fetch)."""
    if not isinstance(doc, dict) or not isinstance(doc.get("files"), list):
        warnings.append("guarddog.native.json: not the kit's guarddog record (no files list) -> no rows")
        return []
    out = []
    for entry in doc["files"]:
        if not isinstance(entry, dict):
            continue
        eco, manifest = str(entry.get("ecosystem") or "?"), str(entry.get("manifest") or "")
        norm = _pypi_name if eco == "pypi" else str.lower
        items = entry.get("verify") if isinstance(entry.get("verify"), list) else []
        seen = {norm(str((i or {}).get("dependency") or "")) for i in items if isinstance(i, dict)}
        missing = [n for n in entry.get("requested") or [] if n not in seen]
        if missing:
            warnings.append(f"guarddog: {manifest}: {len(missing)} package(s) not checked "
                            f"(guarddog returned nothing for them): {', '.join(missing[:20])}")
        for it in items:
            if not isinstance(it, dict):
                continue
            name, version = str(it.get("dependency") or "?"), str(it.get("version") or "")
            r = it.get("result") if isinstance(it.get("result"), dict) else {}
            errs = "; ".join(f"{k}: {v}" for k, v in (r.get("errors") or {}).items())
            if r.get("results") is None:
                warnings.append(f"guarddog: {name} {version} not scanned ({' '.join((errs or 'no results').split())[:200]})")
                continue
            if errs:   # one rule failing (a timeout, seen live) leaves the others' results standing
                warnings.append(f"guarddog: {name} {version}: some rules did not run ({' '.join(errs.split())[:200]})")
            sev_of = {}
            rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            for risk in r.get("risks") or []:
                if isinstance(risk, dict) and risk.get("threat_rule"):
                    s = str(risk.get("severity") or "").lower()
                    if rank.get(s, 0) > rank.get(sev_of.get(risk["threat_rule"]), 0):
                        sev_of[risk["threat_rule"]] = s
            label = str((r.get("risk_score") or {}).get("label") or "")
            for rule, hits in (r.get("results") or {}).items():
                if not hits or str(rule).startswith("capability-"):
                    continue
                first = hits[0].get("location") if isinstance(hits, list) and hits and isinstance(hits[0], dict) \
                    else str(hits).splitlines()[0][:200]
                sev = sev_of.get(rule)
                out.append({
                    "id": _id("guarddog", rule, f"{eco}:{norm(name)}|{manifest}"),
                    "dimension": "guarddog",
                    "tool": "guarddog",
                    "rule_id": rule,
                    "file": manifest or None,
                    "line": None,
                    "message": f"{name} {version}: {rule}" + (f" (package risk: {label})" if label else ""),
                    "severity": sev or "unknown",
                    "severity_source": f"guarddog:{sev or 'none'}",
                    "cvss": None,
                    "decision": None,
                    "confidence": None,
                    "evidence": None,
                    "package": {"ecosystem": eco, "name": name, "version": version},
                    "detail": first,
                })
    return out


def guarddog_add(ecosystem: str, manifest: str, verify_path: str, record_path: str) -> int:
    """Append one `guarddog <eco> verify <manifest> --output-format json` run to the kit's record,
    with the packages the manifest asked for, and print what fired. 2 = the output is not JSON."""
    try:
        verify = json.load(open(verify_path, encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"guarddog: {manifest}: output unreadable ({exc.__class__.__name__})")
        return 2
    if not isinstance(verify, list):
        print(f"guarddog: {manifest}: output is not a verify list")
        return 2
    try:
        record = json.load(open(record_path, encoding="utf-8"))
    except (OSError, ValueError):
        record = {"files": []}
    entry = {"ecosystem": ecosystem, "manifest": manifest,
             "requested": requested_packages(ecosystem, manifest), "verify": verify}
    record["files"].append(entry)
    with open(record_path, "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=1)
    warnings: list = []
    rows = parse_guarddog({"files": [entry]}, warnings)
    for r in rows:
        print(f"  {r['message']} [{r['severity']}]")
    for w in warnings:
        print(f"  ! {w}")
    print(f"guarddog: {manifest}: {len(verify)} of {len(entry['requested'])} package(s) checked, "
          f"{len(rows)} non-capability rule(s) fired")
    return 0


def guarddog_gate(record_path: str, block_extra: str = "", report_extra: str = "") -> int:
    """The guarddog dimension's verdict, from what fired, not from guarddog's exit code: that counts
    capability-* rules too, so `requests` alone made it 1. Blocking uses pkgcheck's measured block
    list (the pre-install check's), with the same overrides. 1 = a block-list rule fired; 4 = rules
    fired, none on it (reported, not blocking); 0 = none; 2 = the record is unreadable."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import pkgcheck
    try:
        doc = json.load(open(record_path, encoding="utf-8"))
    except (OSError, ValueError):
        print("guarddog: no readable record")
        return 2
    rows = parse_guarddog(doc, [])
    csv = lambda v: {x.strip() for x in (v or "").split(",") if x.strip()}
    block = (set(pkgcheck.BLOCK_RULES) | csv(block_extra)) - csv(report_extra)
    blocking = sorted({f"{r['package']['name']}: {r['rule_id']}" for r in rows if r["rule_id"] in block})
    if blocking:
        print(f"guarddog: BLOCK — {', '.join(blocking)}")
        return 1
    if rows:
        print(f"guarddog: {len(rows)} rule(s) fired, none on the block list -> reported, not blocking")
        return 4
    print("guarddog: no threat or metadata rule fired (capability-* rules are not findings)")
    return 0


NPM_SEVERITY = {"critical": "critical", "high": "high", "moderate": "medium", "low": "low", "info": "info"}


def _lockfile(d: str) -> str:
    return "package-lock.json" if d in ("", ".") else f"{d.rstrip('/')}/package-lock.json"


def parse_npm_audit(doc, warnings: list) -> list:
    """The kit's npm audit record (one `npm audit --json` report per JS project, auditReportVersion 2)
    -> rows: one per package and advisory. npm's own severity (moderate = medium) and the advisory's
    CVSS, which comes from the GitHub advisory, so it is a score and not a guess. A package listed only
    because it depends on a vulnerable one carries no advisory of its own and is not a row."""
    if not isinstance(doc, dict) or not isinstance(doc.get("dirs"), list):
        warnings.append("npm-audit.native.json: not the kit's npm audit record (no dirs list) -> no rows")
        return []
    out = []
    for entry in doc["dirs"]:
        if not isinstance(entry, dict) or not isinstance((entry.get("audit") or {}).get("vulnerabilities"), dict):
            continue
        lock = _lockfile(str(entry.get("dir") or "."))
        for pkg, v in entry["audit"]["vulnerabilities"].items():
            if not isinstance(v, dict):
                continue
            fix = v.get("fixAvailable")
            fixed_in = [str(fix["version"])] if isinstance(fix, dict) and fix.get("version") else []
            seen = set()
            for via in v.get("via") or []:
                if not isinstance(via, dict):
                    continue            # a package name: the advisory is listed under that package
                url = str(via.get("url") or "")
                adv = url.rsplit("/", 1)[-1] if "/advisories/GHSA-" in url else f"npm-{via.get('source')}"
                if adv in seen:
                    continue
                seen.add(adv)
                sev = NPM_SEVERITY.get(str(via.get("severity") or "").lower())
                score = (via.get("cvss") or {}).get("score")
                out.append({
                    "id": _id("js-deps", adv, f"npm:{pkg}|{lock}"),
                    "dimension": "js-deps",
                    "tool": "npm-audit",
                    "rule_id": adv,
                    "file": lock,
                    "line": None,
                    "message": f"{pkg} {via.get('range') or v.get('range') or ''}: {via.get('title') or adv}"
                               + (f", fixed in {fixed_in[0]}" if fixed_in else ""),
                    "severity": sev or "unknown",
                    "severity_source": f"npm:{via.get('severity') or 'none'}",
                    "cvss": float(score) if isinstance(score, (int, float)) and score > 0 else None,
                    "decision": None,
                    "confidence": None,
                    "evidence": None,
                    "package": {"ecosystem": "npm", "name": pkg, "version": None},
                    "affected": str(via.get("range") or ""),
                    "direct": bool(v.get("isDirect")),
                    "fixed_in": fixed_in,
                })
    return out


def npm_add(directory: str, audit_path: str, record_path: str) -> int:
    """Append one `npm audit --json` report to the kit's record and print what it found.
    2 = no report: npm wrote an error object or nothing readable (a scan error, not findings)."""
    try:
        audit = json.load(open(audit_path, encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"npm audit: {directory}: output unreadable ({exc.__class__.__name__})")
        return 2
    if not isinstance(audit, dict) or not isinstance(audit.get("vulnerabilities"), dict):
        err = audit.get("error") if isinstance(audit, dict) else None
        why = (f"{err.get('code')}: {' '.join(str(err.get('summary') or '').split())[:200]}"
               if isinstance(err, dict) else "no vulnerabilities report")
        print(f"npm audit: {directory}: {why}")
        return 2
    try:
        record = json.load(open(record_path, encoding="utf-8"))
    except (OSError, ValueError):
        record = {"dirs": []}
    record["dirs"].append({"dir": directory, "audit": audit})
    with open(record_path, "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=1)
    rows = parse_npm_audit({"dirs": [record["dirs"][-1]]}, [])
    for r in rows:
        print(f"  {r['message']} [{r['severity']}]")
    print(f"npm audit: {directory}: {len(rows)} advisor{'y' if len(rows) == 1 else 'ies'} "
          f"in {len({r['package']['name'] for r in rows})} package(s)")
    return 0


PARSERS = {"pip-audit": parse_pip_audit, "checkov": parse_checkov, "guarddog": parse_guarddog,
           "npm-audit": parse_npm_audit}


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


def summary_osv_sarif(path: str) -> int:
    """Readable lines for the scan log from osv-scanner's SARIF (py-deps with no venv). Each result's
    message already names the package, version, advisory and its other ids; one line per result."""
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError, RecursionError) as exc:
        print(f"osv-scanner: SARIF unreadable ({exc.__class__.__name__})")
        return 2
    lines = []
    for run in doc.get("runs") or [] if isinstance(doc, dict) else []:
        for res in (run.get("results") or []) if isinstance(run, dict) else []:
            msg = ((res.get("message") or {}).get("text") or "") if isinstance(res, dict) else ""
            loc = ""
            try:
                loc = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].replace("file:///repo/", "")
            except (KeyError, IndexError, TypeError, AttributeError):
                pass
            line = " ".join(str(msg).split())[:300] + (f"  [{loc}]" if loc else "")
            if line.strip() and line not in lines:
                lines.append(line)
    for line in lines:
        print(f"  {line}")
    print(f"osv-scanner: {len(lines)} known vulnerabilit{'y' if len(lines) == 1 else 'ies'} (manifest, static)")
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "summary" and sys.argv[2] == "pip-audit":
        sys.exit(summary(sys.argv[2], sys.argv[3]))
    if len(sys.argv) == 4 and sys.argv[1] == "summary" and sys.argv[2] == "osv-sarif":
        sys.exit(summary_osv_sarif(sys.argv[3]))
    if len(sys.argv) == 6 and sys.argv[1] == "guarddog-add" and sys.argv[2] in ("pypi", "npm"):
        sys.exit(guarddog_add(*sys.argv[2:6]))
    if len(sys.argv) == 5 and sys.argv[1] == "npm-add":
        sys.exit(npm_add(*sys.argv[2:5]))
    if 3 <= len(sys.argv) <= 5 and sys.argv[1] == "guarddog-gate":
        sys.exit(guarddog_gate(*sys.argv[2:5]))
    print("usage: native.py summary pip-audit <file> | guarddog-add <pypi|npm> <manifest> <verify.json> <record.json>",
          file=sys.stderr)
    sys.exit(2)
