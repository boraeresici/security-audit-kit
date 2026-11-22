# `decisions.json`: a person's decision about a finding

Path: `docs/security/decisions.json`, committed. Written **only** by `scan.sh decide`
(`lib/decisions.py`), so it stays valid, sorted and diffable. Schema id:
`security-audit-kit/decisions@1`.

The kit keeps three layers apart, each with one writer (F19a):

| Layer | File | Written by |
|---|---|---|
| What the scanners found | `evidence.json` (rebuilt on every scan) | `scan.sh` |
| What the AI pass judged | `findings-<date>.md` | the skills (`/sec-triage`, …) |
| What a person decided | `decisions.json` (committed) | `scan.sh decide` |

## What a decision does, and does not do

- It is **on record**: who decided what about which finding, why, on what kind of evidence, and
  until when.
- It does **not change the gate.** A `rejected` or `accepted` decision never unblocks a commit or a
  push. The file is committed, so whoever writes a branch writes it too; if it could unblock, it
  would be a suppression list with no reviewer. To stop a finding from blocking, use the scanner's
  own allowlist (`scan.sh allowlist` audits them).
- Showing decisions next to findings (in `evidence.json` and the HTML report) is the next slice.

## Command

```
scan.sh decide <fingerprint> <decision> --reason "<why>" [--owner N] [--until YYYY-MM-DD]
               [--evidence-kind observed|inferred|unverified] [--verify "<what>"]
scan.sh decide list | check | remove <fingerprint>
scan.sh decide                      # the full help
```

- The fingerprint comes from `evidence.json` or from *details* in the HTML report. A unique prefix
  of at least 8 characters is enough; an ambiguous one is refused. It must be in the **current**
  `evidence.json`: a decision is about something the scan reported.
- `--owner` defaults to `git config user.name`.
- A second decision about the same fingerprint replaces the first. `remove` deletes one.
- `list` marks a decision `EXPIRED` once its `until` date has passed, and `not-seen` when the last
  scan did not report its finding (fixed, renamed, or a dimension that did not run). `check` exits
  1 on an expired decision, for CI.

## Entry

```json
{
  "fingerprint": "3f9c2a1b7d0e4c5a9b8e",
  "decision": "rejected",
  "evidence_kind": "observed",
  "reason": "the parser is never called with user input",
  "owner": "Ada",
  "decided": "2026-11-22",
  "until": null,
  "verify": null,
  "subject": {
    "dimension": "osv", "tool": "osv-scanner", "rule_id": "CVE-2021-33503",
    "file": "requirements.txt", "line": null, "fingerprint_basis": "package",
    "tools": ["osv-scanner", "trivy"],
    "package": {"ecosystem": "pypi", "name": "urllib3", "version": "1.26.4"},
    "aliases": ["CVE-2021-33503", "GHSA-q2q7-5pp4-w6pg", "PYSEC-2021-108"],
    "message": "Package 'urllib3@1.26.4' is vulnerable to 'CVE-2021-33503' …"
  }
}
```

| Field | Rule |
|---|---|
| `fingerprint` | 20 hex; unique in the file. |
| `decision` | `confirmed` (real; fix it) · `rejected` (a false positive: the claim does not hold here) · `accepted` (real, risk accepted until `until`) · `needs-validation` (cannot be settled from the code). The AI pass's REAL / FP / UNCERTAIN are not mapped onto these automatically. |
| `evidence_kind` | `observed` (tool output or a source line) · `inferred` (reasoning over a path) · `unverified` (default). Kept apart from the decision so a reader sees what it rests on. |
| `reason`, `owner` | Required. One line: control, bidi and zero-width characters are removed; at most 2000 / 200 characters. |
| `decided` | The date it was recorded. |
| `until` | A future date. Required for `accepted`, at most 366 days ahead, like a dependency allowlist entry. |
| `verify` | What would settle or re-open it. Required for `needs-validation`. |
| `subject` | The finding as decided. With several rows on one fingerprint (two tools, one advisory) it keeps every tool and the union of their names, so the decision stays findable when an advisory gains another id. |

A file that is not valid JSON, has another schema, or breaks one of these rules is refused, never
overwritten: it is a committed file and may hold other people's decisions. Fix it, or restore it
from git.
