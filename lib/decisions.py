#!/usr/bin/env python3
"""The human decision record (F19a, slice 3): docs/security/decisions.json, written by `scan.sh decide`.

One writer per layer (user decision, 2026-11-17): scanner records live in evidence.json, the AI's
judgment in the findings markdown, and a person's decision HERE, written only by this CLI so the
file stays valid and diffable. A decision is keyed on a finding's `fingerprint` (F19a S1/S2) and
keeps a snapshot of the finding as it was when decided: its rule, file, line, package and
aliases. The snapshot is what lets a later slice say "decided about this, and the code has since
changed", and what keeps a decision findable when an advisory gains a new name.

What a decision does NOT do in this slice: change the gate. A decision is on record, nothing more.
The file is committed, so whoever writes a branch writes it too; letting it unblock a push would
turn it into a suppression list with no expiry check and no reviewer. The scanners' own allowlists
remain the only way to stop a finding from blocking.

Stdlib only. Usage (via scan.sh, which passes the paths):
  decisions.py set    <record> <evidence> <fingerprint> <decision> --reason T [--owner N]
                      [--until YYYY-MM-DD] [--evidence-kind K] [--verify T] [--date YYYY-MM-DD]
  decisions.py remove <record> <fingerprint>
  decisions.py list   <record> [<evidence>]
  decisions.py check  <record>
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
import tempfile
import unicodedata

SCHEMA = "security-audit-kit/decisions@1"
DECISIONS = {
    "confirmed": "a real finding; fix it",
    "rejected": "a false positive: the claim does not hold here",
    "accepted": "real, and the risk is accepted until a date (needs --until)",
    "needs-validation": "cannot be settled from the code; say what would settle it (--verify)",
}
EVIDENCE_KINDS = ("observed", "inferred", "unverified")
FP_RE = re.compile(r"^[0-9a-f]{20}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MAX_TEXT = 2000
MAX_OWNER = 200
MAX_ACCEPT_DAYS = 366       # an accepted risk comes back within a year, like a dependency allowlist
SNAPSHOT_KEYS = ("dimension", "tool", "rule_id", "file", "line", "fingerprint_basis")


class Refused(Exception):
    """A request the record must not take. The message is what the user reads."""


def clean(text, limit: int, what: str) -> str:
    """One line of prose: no control, bidi or zero-width characters (the record is read in a
    terminal, in diffs and in the HTML report), whitespace collapsed, length capped."""
    if not isinstance(text, str):
        raise Refused(f"{what}: expected text")
    out = "".join(" " if unicodedata.category(c) in ("Cc", "Zl", "Zp") else c for c in text
                  if unicodedata.category(c) != "Cf")
    out = " ".join(out.split())
    if len(out) > limit:
        raise Refused(f"{what}: at most {limit} characters (got {len(out)})")
    return out


def valid_date(text: str, what: str) -> datetime.date:
    if not isinstance(text, str) or not DATE_RE.match(text):
        raise Refused(f"{what}: expected YYYY-MM-DD, got {text!r}")
    try:
        return datetime.date.fromisoformat(text)
    except ValueError:
        raise Refused(f"{what}: {text} is not a date") from None


def empty() -> dict:
    return {"schema": SCHEMA, "decisions": []}


def load(path: str) -> dict:
    """The record, validated. A missing file is an empty record; a broken one is refused, never
    silently replaced: it is a committed file and may hold other people's decisions."""
    if not os.path.exists(path):
        return empty()
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        raise Refused(f"{path}: not readable JSON ({exc.__class__.__name__}) — fix or restore it from git") from None
    problems = validate(doc)
    if problems:
        raise Refused(f"{path}: " + "; ".join(problems[:5]) + (f" (+{len(problems) - 5} more)" if len(problems) > 5 else ""))
    return doc


def validate(doc) -> list:
    """-> problems; empty means the record is well-formed."""
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA or not isinstance(doc.get("decisions"), list):
        return [f"not a {SCHEMA} document"]
    problems, seen = [], set()
    for i, d in enumerate(doc["decisions"]):
        where = f"decision {i}"
        if not isinstance(d, dict):
            problems.append(f"{where}: not an object")
            continue
        fp = d.get("fingerprint")
        if not isinstance(fp, str) or not FP_RE.match(fp):
            problems.append(f"{where}: fingerprint must be 20 hex characters")
        elif fp in seen:
            problems.append(f"{where}: fingerprint {fp} is decided twice")
        else:
            seen.add(fp)
        if d.get("decision") not in DECISIONS:
            problems.append(f"{where}: decision must be one of {', '.join(DECISIONS)}")
        if d.get("evidence_kind") not in EVIDENCE_KINDS:
            problems.append(f"{where}: evidence_kind must be one of {', '.join(EVIDENCE_KINDS)}")
        for key in ("reason", "owner"):
            if not isinstance(d.get(key), str) or not d[key].strip():
                problems.append(f"{where}: {key} is required")
        for key in ("decided", "until"):
            if d.get(key) is not None:
                try:
                    valid_date(d[key], f"{where}: {key}")
                except Refused as exc:
                    problems.append(str(exc))
        if d.get("decision") == "accepted" and not d.get("until"):
            problems.append(f"{where}: an accepted risk needs an until date")
        if not isinstance(d.get("subject"), dict):
            problems.append(f"{where}: subject (the finding as decided) is required")
        elif d["subject"].get("package") is not None and not isinstance(d["subject"]["package"], dict):
            problems.append(f"{where}: subject.package must be an object")
    return problems


# Builder warnings about the record. A view that lays the current record over an older
# evidence.json (the local UI, R13c) drops these and says its own: they describe the record as
# it was when the scan ran.
WARN_NOT_USED = "decisions.json not used: "
WARN_UNSEEN = " decision(s) in decisions.json are about findings this scan did not report"


def apply_reviews(findings: list, record, warnings: list) -> dict:
    """A person's decision shown on the finding it is about: sets `review` on each decided finding,
    and returns the count per decision (plus "none"). Display only. `record` is a validated
    decisions document, or None.

    Whether a decision is past its `until` date is NOT decided here: that depends on today's date,
    and evidence.json must diff to nothing over unchanged code. What is decided here, from content
    alone: whether the finding changed since the decision (the package version it was decided at).
    The record is branch-authored, so every field read is type-checked first."""
    counts = {d: 0 for d in DECISIONS}
    counts["none"] = 0
    by_fp = {d["fingerprint"]: d for d in (record or {}).get("decisions") or [] if isinstance(d, dict)}
    seen = set()
    for f in findings:
        d = by_fp.get(f.get("fingerprint"))
        if not d or d.get("decision") not in DECISIONS:
            counts["none"] += 1
            continue
        seen.add(d["fingerprint"])
        changed = []
        subject = d.get("subject") if isinstance(d.get("subject"), dict) else {}
        then_pkg = subject.get("package") if isinstance(subject.get("package"), dict) else {}
        now_pkg = f.get("package") if isinstance(f.get("package"), dict) else {}
        then, now = then_pkg.get("version"), now_pkg.get("version")
        if then and now and then != now:
            changed.append(f"package version {then} -> {now}")
        f["review"] = {k: d.get(k) for k in ("decision", "evidence_kind", "reason", "owner", "decided", "until", "verify")}
        f["review"]["changed"] = changed
        counts[d["decision"]] += 1
    unseen = len(set(by_fp) - seen)
    if unseen:
        warnings.append(f"{unseen}{WARN_UNSEEN} (fixed, renamed, or a dimension that did not run) — scan.sh decide list")
    return counts


def save(path: str, doc: dict) -> None:
    """Sorted, indented, newline-terminated, written then renamed: the file is diffable and a
    crash mid-write leaves the old one whole."""
    doc = {"schema": SCHEMA, "decisions": sorted(doc["decisions"], key=lambda d: d["fingerprint"])}
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)), prefix=".decisions.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def findings_by_fingerprint(evidence_path: str) -> dict:
    try:
        with open(evidence_path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        raise Refused(f"no readable evidence.json at {evidence_path} — run a scan with SARIF=1 (or scan.sh evidence) first") from None
    out = {}
    for f in doc.get("findings") or []:
        if isinstance(f, dict) and isinstance(f.get("fingerprint"), str):
            out.setdefault(f["fingerprint"], []).append(f)
    return out


def resolve(fingerprint: str, known: dict) -> str:
    """A full fingerprint, or a unique prefix of at least 8 characters (what the report shows is
    long to type). An ambiguous prefix is refused: deciding about the wrong finding is worse than
    asking for two more characters."""
    fp = (fingerprint or "").strip().lower()
    if FP_RE.match(fp):
        return fp
    if not re.match(r"^[0-9a-f]{8,19}$", fp):
        raise Refused(f"fingerprint: expected 20 hex characters (or a unique prefix of at least 8), got {fingerprint!r}")
    hits = sorted(k for k in known if k.startswith(fp))
    if not hits:
        raise Refused(f"fingerprint {fp}…: no finding in evidence.json starts with it")
    if len(hits) > 1:
        raise Refused(f"fingerprint {fp}… matches {len(hits)} findings ({', '.join(h[:12] for h in hits[:4])}…): give more characters")
    return hits[0]


def snapshot(rows: list) -> dict:
    """The finding as decided. Several rows can share a fingerprint (two tools, one advisory): the
    snapshot keeps every tool and the union of their aliases, so a later rename still finds it."""
    first = rows[0]
    snap = {k: first.get(k) for k in SNAPSHOT_KEYS}
    snap["tools"] = sorted({str(r.get("tool")) for r in rows if r.get("tool")})
    pkg = first.get("package")
    if isinstance(pkg, dict):
        snap["package"] = {k: pkg.get(k) for k in ("ecosystem", "name", "version")}
    aliases = sorted({a for r in rows for a in (r.get("aliases") or []) if isinstance(a, str)}
                     | {str(r.get("rule_id")) for r in rows if r.get("rule_id")})
    if len(aliases) > 1:
        snap["aliases"] = aliases
    snap["message"] = clean(str(first.get("message") or ""), MAX_TEXT, "message")
    return snap


def cmd_set(a) -> int:
    known = findings_by_fingerprint(a.evidence)
    fp = resolve(a.fingerprint, known)
    if fp not in known:
        raise Refused(f"fingerprint {fp}: not in the current evidence.json — decide about what this scan found "
                      "(scan.sh report shows each finding's fingerprint under details)")
    if a.decision not in DECISIONS:
        raise Refused(f"decision must be one of: {', '.join(DECISIONS)}")
    reason = clean(a.reason or "", MAX_TEXT, "--reason")
    if not reason:
        raise Refused("--reason is required: a decision nobody can read the why of is not reviewable")
    owner = clean(a.owner or "", MAX_OWNER, "--owner")
    if not owner:
        raise Refused("--owner is required (or set git's user.name)")
    today = valid_date(a.date, "--date") if a.date else datetime.date.today()
    until = None
    if a.until:
        u = valid_date(a.until, "--until")
        if u <= today:
            raise Refused(f"--until {a.until} is not in the future")
        if a.decision == "accepted" and (u - today).days > MAX_ACCEPT_DAYS:
            raise Refused(f"--until {a.until}: an accepted risk is reviewed within {MAX_ACCEPT_DAYS} days")
        until = a.until
    if a.decision == "accepted" and not until:
        raise Refused("an accepted risk needs --until YYYY-MM-DD (it must come back for review)")
    verify = clean(a.verify or "", MAX_TEXT, "--verify") or None
    if a.decision == "needs-validation" and not verify:
        raise Refused("needs-validation needs --verify: say what would settle it")

    doc = load(a.record)
    old = next((d for d in doc["decisions"] if d["fingerprint"] == fp), None)
    entry = {
        "fingerprint": fp,
        "decision": a.decision,
        "evidence_kind": a.evidence_kind,
        "reason": reason,
        "owner": owner,
        "decided": today.isoformat(),
        "until": until,
        "verify": verify,
        "subject": snapshot(known[fp]),
    }
    doc["decisions"] = [d for d in doc["decisions"] if d["fingerprint"] != fp] + [entry]
    save(a.record, doc)
    s = entry["subject"]
    where = s.get("file") or (s.get("package") or {}).get("name") or "-"
    verb = "replaced" if old else "recorded"
    print(f"decide: {verb} {fp[:12]} {a.decision} — {s.get('rule_id')} {where}"
          + (f" (was {old['decision']})" if old else "") + (f", until {until}" if until else ""))
    print(f"decide: {os.path.relpath(a.record)} is a committed file; commit it with the change it explains."
          " It does not change what blocks a push.")
    return 0


def cmd_remove(a) -> int:
    doc = load(a.record)
    fp = (a.fingerprint or "").strip().lower()
    hits = [d for d in doc["decisions"] if d["fingerprint"] == fp or (len(fp) >= 8 and d["fingerprint"].startswith(fp))]
    if len(hits) != 1:
        raise Refused(f"fingerprint {fp}: {'no decision' if not hits else f'{len(hits)} decisions'} match — give the full fingerprint")
    doc["decisions"] = [d for d in doc["decisions"] if d is not hits[0]]
    save(a.record, doc)
    print(f"decide: removed {hits[0]['fingerprint'][:12]} ({hits[0]['decision']})")
    return 0


def status_of(d: dict, known, today: datetime.date) -> str:
    if d.get("until") and valid_date(d["until"], "until") < today:
        return "EXPIRED"
    if known is not None and d["fingerprint"] not in known:
        return "not-seen"              # fixed, renamed, or a dimension that did not run
    return "ok"


def cmd_list(a) -> int:
    doc = load(a.record)
    known = findings_by_fingerprint(a.evidence) if a.evidence and os.path.exists(a.evidence) else None
    today = datetime.date.today()
    if not doc["decisions"]:
        print(f"decide: no decisions in {os.path.relpath(a.record)}")
        return 0
    for d in doc["decisions"]:
        s = d["subject"]
        where = s.get("file") or (s.get("package") or {}).get("name") or "-"
        print(f"  {d['fingerprint'][:12]}  {d['decision']:<16} {status_of(d, known, today):<8} "
              f"{d['decided']}{' until ' + d['until'] if d.get('until') else ''}  {s.get('rule_id')}  {where}  ({d['owner']})")
    if known is None:
        print("  (no evidence.json: 'not-seen' is not checked)")
    return 0


def cmd_check(a) -> int:
    doc = load(a.record)
    today = datetime.date.today()
    expired = [d for d in doc["decisions"] if status_of(d, None, today) == "EXPIRED"]
    for d in expired:
        print(f"  !!  decision {d['fingerprint'][:12]} ({d['decision']}) expired {d['until']} — review it: scan.sh decide")
    print(f"decide: {len(doc['decisions'])} decision(s), {len(expired)} expired")
    return 1 if expired else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="scan.sh decide", description="Record a person's decision about a finding.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("set")
    s.add_argument("record"); s.add_argument("evidence"); s.add_argument("fingerprint"); s.add_argument("decision")
    s.add_argument("--reason"); s.add_argument("--owner"); s.add_argument("--until"); s.add_argument("--verify")
    s.add_argument("--evidence-kind", default="unverified", choices=EVIDENCE_KINDS)
    s.add_argument("--date", help=argparse.SUPPRESS)          # tests: a fixed "today"
    r = sub.add_parser("remove"); r.add_argument("record"); r.add_argument("fingerprint")
    li = sub.add_parser("list"); li.add_argument("record"); li.add_argument("evidence", nargs="?")
    c = sub.add_parser("check"); c.add_argument("record")
    a = ap.parse_args(argv)
    try:
        return {"set": cmd_set, "remove": cmd_remove, "list": cmd_list, "check": cmd_check}[a.cmd](a)
    except Refused as exc:
        print(f"decide: REFUSED — {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
