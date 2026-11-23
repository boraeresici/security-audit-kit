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
import math
import os
import re
import sys
import unicodedata

import decisions
import fingerprint
import native

SCHEMA = "security-audit-kit/evidence@1"

# SARIF file -> (tool name, scan.sh dimension). The dimension is what lets us include only the
# findings this run actually produced: the sarif/ directory persists between scans.
SARIF_SOURCES = {
    "gitleaks.sarif": ("gitleaks", "secret"),
    "semgrep.sarif": ("semgrep", "sast"),
    "trivy.sarif": ("trivy", "container"),
    "osv.sarif": ("osv-scanner", "osv"),
    # py-deps with no project venv: osv-scanner reads the committed manifests statically
    "py-deps-osv.sarif": ("osv-scanner", "py-deps"),
    "zizmor.sarif": ("zizmor", "zizmor"),
}

# Every per-finding output the builder reads: SARIF, and the native JSON of tools without it (F16b).
SOURCES = {**SARIF_SOURCES, **native.NATIVE_SOURCES}

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
# `unknown`: the tool gave no severity (pip-audit) — never guessed, never folded into `info`.
SEVERITIES = ("critical", "high", "medium", "low", "unknown", "info")


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
        score = float(raw)
    except (TypeError, ValueError):
        return None
    return score if math.isfinite(score) else None   # "NaN" from a tool must not reach the JSON


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
    if not raw or raw.lower() in {"-", "—", "–", "n/a", "none"}:
        return None, None
    if ":" in raw:
        head, _, tail = raw.rpartition(":")
        if head and _is_line(tail):
            # path:line:column -> the column goes; the line is the number before it
            h2, _, t2 = head.rpartition(":")
            if h2 and _is_line(t2):
                head, tail = h2, t2
            return head.strip(), int(tail)
    return raw, None


def _is_line(s: str) -> bool:
    # ASCII only ("²" is a digit to isdigit(), not to int()), and short: int() refuses 4300+ digits.
    return s.isascii() and s.isdigit() and len(s) <= 9


# The findings table is written by a model that read the scanned repo, so its cells are untrusted
# input: the path goes on into kit.sarif's artifactLocation, which is uploaded to Code Scanning.
MAX_FINDINGS_BYTES = 2 * 1024 * 1024
MAX_CELL_CHARS = 2000
MAX_PATH_CHARS = 1024
MAX_LINE = 10_000_000
MAX_ROW_WARNINGS = 20
# Bidirectional controls, zero-width space, BOM and tag characters: they reorder or hide text.
# Other format characters (ZWJ in emoji, ZWNJ in Persian, the soft hyphen) are kept in free text.
_HIDING = (set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200B, 0x200E, 0x200F, 0x061C, 0xFEFF}
           | set(range(0xE0000, 0xE0080)))


def _unsafe_char(c: str) -> bool:
    """Not in a path: control, format, separator, private-use, unassigned and non-ASCII spaces."""
    cat = unicodedata.category(c)
    return cat in ("Cc", "Cf", "Zl", "Zp", "Co", "Cn") or (cat == "Zs" and c != " ")


def safe_location(path: str, line):
    """-> the repo-relative path to keep, or None when the location must not be trusted."""
    while path.startswith("./"):
        path = path[2:]
    if not path or len(path) > MAX_PATH_CHARS or any(_unsafe_char(c) for c in path):
        return None
    # A colon is a URI scheme or a drive letter; a backslash is a Windows separator.
    if "\\" in path or ":" in path or path.startswith(("/", "~")):
        return None
    # Fullwidth "．．" becomes ".." under compatibility normalization; NFD (macOS) names stay valid.
    if unicodedata.normalize("NFKC", path) != unicodedata.normalize("NFC", path):
        return None
    for seg in path.split("/"):
        # Windows drops a trailing dot or space, so "..." and ".. " would become "..".
        if seg in ("", ".", "..") or seg != seg.lstrip(" ") or seg.endswith((".", " ")):
            return None
    if line is not None and not 1 <= line <= MAX_LINE:
        return None
    return path


def clean_cell(text: str) -> str:
    """Free text bound for evidence.json, kit.sarif and the report: no control or bidi characters."""
    out = "".join(" " if unicodedata.category(c) in ("Cc", "Zl", "Zp") else c
                  for c in text if ord(c) not in _HIDING)
    return out if len(out) <= MAX_CELL_CHARS else out[:MAX_CELL_CHARS - 1] + "…"


def slug(text: str, fallback: str) -> str:
    keep = [c.lower() if c.isalnum() else "-" for c in text.strip()]
    out = "".join(keep).strip("-")
    while "--" in out:
        out = out.replace("--", "-")
    return out[:48] or fallback


def parse_findings_md(path: str, warnings: list) -> list:
    """-> judgment findings: [{origin, tool, rule_id, file, line, severity, decision, ...}]."""
    try:
        if os.path.getsize(path) > MAX_FINDINGS_BYTES:
            warnings.append(f"findings file is over {MAX_FINDINGS_BYTES // (1024 * 1024)} MiB -> judgment layer skipped")
            return []
        # Split on newlines only: splitlines() also breaks at U+2028 and friends, which would cut a
        # row in two before its cells are checked.
        with open(path, encoding="utf-8-sig", newline="") as fh:
            lines = [ln.rstrip("\r") for ln in fh.read().split("\n")]
    except FileNotFoundError:
        return []
    except (OSError, UnicodeDecodeError) as exc:
        warnings.append(f"findings file unreadable ({exc.__class__.__name__}) -> judgment layer skipped")
        return []

    origin = "sec-triage"
    dropped = 0
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
        # The path is checked as written, before cleaning: removing a bidi character could turn a
        # rejected path into an accepted one.
        raw_path, line_no = parse_location(row.get("loc", ""))
        if not raw_path:
            continue
        path_ = safe_location(raw_path, line_no)
        if path_ is None:
            dropped += 1
            if dropped <= MAX_ROW_WARNINGS:
                warnings.append(f"findings file: location {ascii(row['loc'].strip())[:120]} is not a safe "
                                "repo-relative path:line -> row dropped")
            continue
        row = {role: clean_cell(value) for role, value in row.items() if role != "loc"}

        sev_raw = row.get("sev", "").strip()[:40]
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
        conf_raw = row.get("conf", "").strip()
        try:
            confidence = float(conf_raw)
        except ValueError:
            pass
        # nan/inf would make evidence.json invalid JSON for strict parsers; "1_0" parses as 10.0.
        if confidence is not None and not (math.isfinite(confidence) and 0 <= confidence <= 1):
            warnings.append(f"findings file: confidence {conf_raw[:40]!r} at {path_} is not in [0, 1] -> none")
            confidence = None

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
    if dropped > MAX_ROW_WARNINGS:
        warnings.append(f"findings file: … and {dropped - MAX_ROW_WARNINGS} more rows dropped for an unsafe location")
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
        prefix = j["tool"].split("-")[0]
        for c in candidates:
            if (prefix and c["tool"].startswith(prefix)) or (len(j["tool"]) > 1 and j["tool"] in c["tool"]):
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


# summary.json statuses (schema 2) under which a dimension's output describes this repo now. Schema 1
# had only pass | fail | indeterminate; "fail" meant findings or a crash, so it stays accepted there.
INSPECTED = {"pass", "findings", "fail"}


def sha256_file(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def select_sources(summary: dict, sarif_dir: str, warnings: list) -> list:
    """The output files (SARIF or native JSON) that are THIS run's findings, as (path, tool, dimension).

    The SARIF directory outlives a run, so "the file is on disk" proves nothing about when it was
    written. summary.json lists what this run produced (`artifacts`, with sha256), and each
    dimension's status; a file is used only if it is in that list, unchanged since, and its
    dimension actually inspected something. Everything left out is said in `warnings`.
    """
    dimensions = summary.get("dimensions") or []
    status = {}
    for d in dimensions:
        status[DIMENSION_ALIASES.get(d.get("name"), d.get("name"))] = d.get("status")
    by_dim = {}
    for fname, (tool, dim) in SOURCES.items():
        by_dim.setdefault(dim, []).append(fname)      # py-deps: pip-audit (venv) or osv-scanner (none)
    on_disk = sorted(f for f in SOURCES if os.path.exists(os.path.join(sarif_dir, f)))

    artifacts = summary.get("artifacts")
    if artifacts is None:
        # Schema 1 / hand-written summary: scope by the dimensions that ran, as before — and say
        # that nothing proves these files belong to that run.
        if dimensions:
            warnings.append("summary.json has no artifact manifest (written before schema 2) -> SARIF "
                            "files on disk are trusted to belong to its run")
            ran = set(status)
        else:
            warnings.append("no summary.json dimensions -> included every SARIF file on disk, which may be stale")
            ran = set(by_dim)
        return [(os.path.join(sarif_dir, f), *SOURCES[f]) for f in on_disk if SOURCES[f][1] in ran]

    listed = {}
    for a in artifacts:
        listed[os.path.basename(a.get("path") or "")] = a.get("sha256")
    out = []
    for fname in sorted(listed):
        if fname not in SOURCES:
            continue
        tool, dim = SOURCES[fname]
        path = os.path.join(sarif_dir, fname)
        st = status.get(dim)
        if st not in INSPECTED:
            warnings.append(f"{fname}: {dim} is '{st}' in this run -> its output is not taken as current findings")
            continue
        if not os.path.exists(path):
            warnings.append(f"{fname}: listed in this run's manifest but missing -> {dim} findings unavailable")
            continue
        if not listed[fname]:
            warnings.append(f"{fname}: no sha256 recorded (no hash tool at scan time) -> used unverified")
        elif sha256_file(path) != listed[fname]:
            warnings.append(f"{fname}: changed since this run wrote it (sha256 mismatch) -> not used")
            continue
        out.append((path, tool, dim))
    for fname in on_disk:
        if fname not in listed:
            warnings.append(f"{fname}: not produced by this run (left over from an earlier one) -> ignored")
    if summary.get("sarif"):
        for dim, st in sorted(status.items()):
            # A dimension that passed has nothing to list; only findings without rows are a gap.
            if st in ("findings", "fail") and dim in by_dim and not any(f in listed for f in by_dim[dim]):
                warnings.append(f"{dim}: has findings, but wrote no per-finding output in this run -> no per-finding rows; see the scan log")
            elif st in ("findings", "fail") and dim not in by_dim:
                # the JS audit, checkov, guarddog: no adapter yet (F16b)
                warnings.append(f"{dim}: has findings, but the kit reads no per-finding output for it yet "
                                "-> not in evidence.json; see the scan log")
    return out


def tool_suppression(result: dict):
    """The tool's own suppression of a result, as a note, or None. A SARIF suppression counts unless
    its status says otherwise (absent = accepted, SARIF 2.1.0 §3.35.3); semgrep writes `nosemgrep`
    hits this way, so without this they were counted as live findings in evidence and the report."""
    for s in result.get("suppressions") or []:
        if not isinstance(s, dict) or (s.get("status") or "accepted") != "accepted":
            continue
        why = " ".join(str(s.get("justification") or "").split())
        return f"suppressed by the tool ({s.get('kind') or 'unspecified'}){': ' + why if why else ''}"
    return None


# Dependency rows that arrive as SARIF (F19a): the package is in the tool's message text, not in a
# field. Both shapes are recorded from the pinned tools (tests/fixtures/native/uvlock/*.sarif); a
# message that does not match adds nothing, and the row keeps its line-content fingerprint.
_OSV_PACKAGE = re.compile(r"^Package '(.+)@([^@']*)' is vulnerable to '")
_TRIVY_FIELD = re.compile(r"^(Package|Installed Version|Fixed Version): (.*)$", re.M)
TRIVY_PACKAGE_RULES = {"LanguageSpecificPackageVulnerability", "OsPackageVulnerability"}
MAX_PACKAGE_CHARS = 200


def sarif_package(tool: str, result: dict, rule: dict, path):
    """-> extra fields for a dependency row ({package, aliases?, fixed_in?}), or {} if it is not one."""
    text = (result.get("message") or {}).get("text") or ""
    if not isinstance(text, str):
        return {}
    name = version = None
    extra = {}
    if tool == "osv-scanner":
        m = _OSV_PACKAGE.match(text)
        if m:
            name, version = m.group(1), m.group(2)
        rule_id = result.get("ruleId")
        known = rule.get("deprecatedIds")
        aliases = sorted({a for a in (known if isinstance(known, list) else []) if isinstance(a, str) and a and a != rule_id})
        if aliases:
            extra["aliases"] = [clean_cell(a)[:MAX_PACKAGE_CHARS] for a in aliases]
    elif tool == "trivy" and rule.get("name") in TRIVY_PACKAGE_RULES:
        fields = dict(_TRIVY_FIELD.findall(text))
        name, version = fields.get("Package"), fields.get("Installed Version")
        fixed = [v.strip() for v in (fields.get("Fixed Version") or "").split(",") if v.strip()]
        if fixed:
            extra["fixed_in"] = [clean_cell(v)[:MAX_PACKAGE_CHARS] for v in fixed]
    name = clean_cell(name or "")[:MAX_PACKAGE_CHARS]
    if not name:
        return {}
    return {"package": {"ecosystem": fingerprint.manifest_ecosystem(path), "name": name,
                        "version": clean_cell(version or "")[:MAX_PACKAGE_CHARS]}, **extra}


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
            suppressed = tool_suppression(result)
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
                "decision": "suppressed" if suppressed else None,
                "confidence": None,
                "evidence": {"sink": f"{path}:{line}" if line else path, "source": None, "note": suppressed} if suppressed else None,
                **sarif_package(tool, result, rules.get(rule_id, {}), path),
            })
    return findings


REVIEWS = tuple(decisions.DECISIONS)


def attach_reviews(findings: list, path: str, warnings: list) -> dict:
    """A person's decision (docs/security/decisions.json, F19a S3) shown on the finding it is about.

    Display only: evidence.json is built after the gate, and nothing here can change it. A record
    that cannot be read is a warning and no reviews, never a failed build — it is a committed,
    branch-authored file. Whether a decision is past its `until` date is NOT decided here: that
    depends on today's date, and evidence.json must diff to nothing over unchanged code. The report
    compares it with its own date. What is decided here, from content alone: whether the finding
    changed since the decision (the package version it was decided at)."""
    counts = {d: 0 for d in REVIEWS}
    counts["none"] = 0
    record = None
    if path and os.path.exists(path):
        try:
            record = decisions.load(path)
        except decisions.Refused as exc:
            warnings.append(f"decisions.json not used: {exc}")
    by_fp = {d["fingerprint"]: d for d in (record or {}).get("decisions") or []}
    seen = set()
    for f in findings:
        d = by_fp.get(f.get("fingerprint"))
        if not d:
            counts["none"] += 1
            continue
        seen.add(d["fingerprint"])
        changed = []
        then = ((d.get("subject") or {}).get("package") or {}).get("version")
        now = (f.get("package") or {}).get("version") if isinstance(f.get("package"), dict) else None
        if then and now and then != now:
            changed.append(f"package version {then} -> {now}")
        f["review"] = {k: d.get(k) for k in ("decision", "evidence_kind", "reason", "owner", "decided", "until", "verify")}
        f["review"]["changed"] = changed
        counts[d["decision"]] += 1
    unseen = len(set(by_fp) - seen)
    if unseen:
        warnings.append(f"{unseen} decision(s) in decisions.json are about findings this scan did not report "
                        "(fixed, renamed, or a dimension that did not run) — scan.sh decide list")
    return counts


def main() -> int:
    ap = argparse.ArgumentParser(description="Build evidence.json from SARIF + summary.json")
    ap.add_argument("--sarif-dir", required=True)
    ap.add_argument("--summary", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--findings", help="findings-<date>.md written by the judgment skills (optional)")
    ap.add_argument("--root", default=".", help="the scanned repo: reported lines are read from it for the fingerprint")
    ap.add_argument("--decisions", help="docs/security/decisions.json: a person's decisions, shown on their findings")
    args = ap.parse_args()

    warnings: list = []
    summary = read_json(args.summary, warnings, "summary.json") or {}
    # Durations are run metadata (they differ on every run), so they stay in summary.json: evidence
    # must still diff to nothing over unchanged code.
    dimensions = [{k: v for k, v in d.items() if k != "seconds"} if isinstance(d, dict) else d
                  for d in (summary.get("dimensions") or [])]

    findings: list = []
    for path, tool, dimension in select_sources(summary, args.sarif_dir, warnings):
        if os.path.basename(path) in native.NATIVE_SOURCES:
            findings.extend(native.PARSERS[tool](read_json(path, warnings, os.path.basename(path)), warnings))
        else:
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

    # The identity a decision keys on (F19a): survives a line shift, where `id` does not.
    fingerprint.assign(findings, args.root)
    by_review = attach_reviews(findings, args.decisions, warnings)

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
            # Content identity (commit, dirty, kit, config, tools, scope) — no run id or time, so
            # two runs over unchanged code still diff to nothing.
            **({"provenance": summary["provenance"]} if summary.get("provenance") else {}),
            # The SARIF list it was built against — content too (paths + sha256), and what lets the
            # report tell whether a summary.json is this evidence's own run.
            **({"artifacts": summary["artifacts"]} if "artifacts" in summary else {}),
        },
        "counts": {"total": len(findings), "by_severity": by_severity, "by_decision": by_decision,
                   "by_review": by_review},
        "findings": findings,
        "warnings": warnings,
    }

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2, sort_keys=False)
        fh.write("\n")
    print(f"[scan:evidence] wrote {args.out} ({len(findings)} findings, {len(warnings)} warnings)")
    for w in warnings:
        print(f"[scan:evidence]   ! {w}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
