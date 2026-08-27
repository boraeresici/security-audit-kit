# `evidence.json` — the kit's normalized finding record (schema v1)

> Status: **shipped in v1.13.0** (T3.1a). It is the single object both planned renderers read —
> `kit.sarif` (T3.1b) and the single-file HTML report (T3.1c). Write renderers against this file,
> never against a tool's native output.

`summary.json` answers *"did the scan pass?"*. `evidence.json` answers *"which findings, where, how
bad, and what did we decide about them?"* — per finding, in one shape, across every dimension.

- **Written by:** `scan.sh evidence` (also run automatically at the end of a scan when `SARIF=1`).
- **Location:** `docs/security/scan-findings/evidence.json`.
- **Input:** the SARIF files in `docs/security/scan-findings/sarif/` plus `summary.json`.
- **Requires:** `python3` and `SARIF=1`. Missing either → the step is skipped with a notice, never
  a failure (same contract as every other optional dimension).

## Design rules

1. **We normalize, we never invent.** `severity` is a normalized bucket derived from what the tool
   said; `severity_source` keeps the tool's own value verbatim so the derivation is auditable.
2. **`cvss` only when a tool supplied a real CVSS-derived score** (trivy, osv-scanner). Semgrep's
   `security-severity` is rule metadata, not a CVSS score for *your* code, so it bands the severity
   but never populates `cvss`. Judgment findings never get a CVSS at all — a scored judgment reads
   as measured when it isn't.
3. **Nothing is dropped.** A value we cannot map becomes `info` and appends a line to `warnings`.
4. **Diffable.** Findings are sorted by `(dimension, file, line, rule_id, id)` and the file carries
   no timestamp — two runs of the same scan over unchanged code produce byte-identical output.
   Volatile metadata (timestamps) stays in `summary.json`.
5. **Only what ran.** The SARIF directory persists between scans, so findings are included only for
   dimensions present in this run's `summary.json`. A `secret`-only scan therefore never resurfaces
   yesterday's `sast` findings. With no `summary.json`, everything is included and a warning is
   recorded.
6. **One finding per identity.** Results sharing an `id` are collapsed and the drop is counted in
   `warnings`. Tools legitimately repeat themselves — osv-scanner emits an advisory once per
   affected package version, which would otherwise report a single CVE in a single manifest line
   two or three times and inflate every count downstream.
7. **Repo-relative paths.** The docker-run tools see the repo mounted at `/repo`, so their SARIF
   carries container paths (`file:///repo/requirements.txt`). The mount is an implementation detail
   and is stripped: a path in `evidence.json` is always relative to the repo root.

## Top-level shape

```json
{
  "schema": "security-audit-kit/evidence@1",
  "scan": {
    "command": "all",
    "exit_code": 1,
    "raw_log": "docs/security/scan-findings/raw-2026-08-12.log",
    "dimensions": [{"name": "sast", "exit_code": 0, "status": "pass"}]
    // status is "pass" | "fail" | "indeterminate". "indeterminate" (exit_code 3) means the
    // dimension RAN but had nothing to inspect — e.g. py-deps with no environment and no manifest
    // readable without building the project. It never blocks, and it must never be read as
    // coverage: treat it as an unanswered question, not a clean result.
  },
  "counts": {
    "total": 3,
    "by_severity": {"critical": 0, "high": 2, "medium": 1, "low": 0, "info": 0},
    "by_decision": {"real": 0, "fp": 0, "suppressed": 0, "undecided": 3}
  },
  "findings": [],
  "warnings": []
}
```

## Finding shape

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Stable 12-hex identity: `sha1(dimension\|rule_id\|file\|line)`. Survives re-scans, so a decision can be attached to it. |
| `dimension` | string | `secret` · `sast` · `container` · `osv` · `zizmor` — the `scan.sh` dimension that produced it. |
| `tool` | string | `gitleaks` · `semgrep` · `trivy` · `osv-scanner` · `zizmor`. |
| `rule_id` | string | The tool's rule / check id, verbatim. |
| `file` | string | Repo-relative path. |
| `line` | int\|null | 1-indexed start line; `null` when the tool reports no location. |
| `message` | string | The tool's message, single-line, trimmed. |
| `severity` | enum | Normalized: `critical` · `high` · `medium` · `low` · `info`. |
| `severity_source` | string | The tool's own value, verbatim, e.g. `semgrep:level=error`, `trivy:security-severity=8.8`. |
| `cvss` | float\|null | Passthrough **only** where the tool supplied a CVSS-derived score. |
| `decision` | enum\|null | `real` · `fp` · `uncertain` · `suppressed` · `null` (not yet judged). Written by the judgment layer, not the scan. |
| `confidence` | float\|null | 0–1, from the triage confidence gate. |
| `evidence` | object\|null | The claim → location chain: `{"sink": "path:line", "source": "…", "note": "…"}`. |

The scan fills everything down to `cvss`; `decision` / `confidence` / `evidence` stay `null` until a
judgment pass (`/sec-triage`) fills them. A renderer must treat `null` as *undecided*, never as *FP*.

## Severity normalization

Numeric first, then the SARIF level, then a tool-specific default:

1. **`properties.security-severity` on the rule** (numeric, GitHub's convention) → CVSS bands:
   `>= 9.0` critical · `>= 7.0` high · `>= 4.0` medium · `> 0` low · `= 0` info.
2. **SARIF `level`** → `error` = high · `warning` = medium · `note` = low · `none` = info.
3. **Tool default** (below) when neither is present.
4. Anything else → `info` + a `warnings` entry.

### Per-tool mapping

| Tool | Native scale | How it maps | `cvss` |
|---|---|---|---|
| **gitleaks** | none — a rule either matched or it didn't | every finding → **high**; a committed credential is not a "warning" | never |
| **semgrep** | `ERROR` / `WARNING` / `INFO`, plus `security-severity` rule metadata | numeric bands when present, else level (`error`→high, `warning`→medium, `info`/`note`→low) | never — the metadata scores the *rule*, not your code |
| **trivy** | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `UNKNOWN`, emitted as `security-severity` | numeric bands; `UNKNOWN` (absent) → level, else **medium** | yes, when numeric |
| **osv-scanner** | CVSS on the advisory, emitted as `security-severity`; every result's SARIF `level` is `warning` regardless | numeric bands (this is where normalization earns its keep — a CVSS 8.9 advisory would otherwise read as a "warning") else level, else **medium** | yes, when numeric |
| **zizmor** | `High` / `Medium` / `Low` (+ its own confidence) | SARIF level (`error`→high, `warning`→medium, `note`→low) | never |
| **judgment skills** (`sec-triage`, `sec-sast-deep`, `sec-ai-review`, `sec-threat-model`) | their own rating in the findings file | carried in as-is via `severity` + `severity_source: "<skill>:<rating>"` when the judgment layer writes back | never |

### Dimensions without per-finding rows (known gap)

`checkov` (iac), `guarddog`, `pip-audit` (py-deps) and the JS audits do not emit SARIF in the kit
today, so they appear in `scan.dimensions` with a pass/fail status but contribute no `findings`
entries. Their findings still reach a human through `raw-<date>.log` and triage. Closing this gap
means adding SARIF output per tool — tracked separately, not part of this schema.

## The judgment half — how decisions get in

The skills write **one** artifact: `findings-<date>.md`, the file a human reads. They are never
asked to also emit JSON — two sources of truth drift, and the markdown is the one people review. So
`scan.sh evidence` parses that file (`--findings`) and folds it in:

- **Tables are read by header name, not column position.** `Sink (file:line)` / `Location`, `Tool`,
  `Untrusted source`, `Sev`, `Conf`, `Decision`, `Action`, `Why`, `Class` / `OWASP` / `Rule` are
  recognised; unknown columns are ignored and a row without a parseable location is skipped with a
  warning. Reordering or adding a column breaks nothing.
- **Section headings set the context.** `## Round N — sec-sast-deep` sets the origin skill; a
  `### Suppressed` heading marks everything under it `decision: suppressed`; a `### Kit issues`
  section is skipped entirely — those are bugs in the kit, not findings about your repo.
- **A triage row about a scanner finding fills that finding in** (matched on file + line, with the
  tool name as a tiebreak) rather than becoming a second entry. A deep-pass finding has no scanner
  counterpart, so it becomes a new finding with `dimension: "judgment"` and `tool: "<skill>"`.

Keep the table shape when editing the skills: it is a machine contract as well as a report.

## `kit.sarif` — the judgment findings in Code Scanning

`lib/kit_sarif.py` renders `evidence.json` into `sarif/kit.sarif` (SARIF 2.1.0, driver
`SecurityAuditKit`, rule ids `SAK-<skill>-<class>`), so the skills' findings land on the same review
surface as the scanners'. The existing self-audit workflow uploads the whole `sarif/` directory, so
nothing needed changing there — and GitHub's upload step validates the document on every push.

- **Scanner findings are not re-reported.** A semgrep hit is already in `semgrep.sarif`; emitting it
  again under a kit rule id would double every alert. Their triage decisions live in `evidence.json`
  (and in the HTML report), not in a second SARIF run.
- **Suppressed findings are emitted as suppressed** (`kind: external`, justification = the triage
  note) — on record, not silently absent. Caveat: SARIF suppressions apply **within a run**, so this
  cannot dismiss another tool's alert from another run; GitHub scopes suppression per run.
- **No `security-severity` property.** That number is read as a CVSS score; a judgment finding has
  none. Ranking rides on the SARIF `level` instead.
- **An empty run is never written.** Zero judgment findings usually means no judgment pass ran, not
  that the findings are gone — and an empty upload closes every open kit alert. With nothing to
  report the previous `kit.sarif` is left untouched.
- Results carry `partialFingerprints.sakFindingId` (the evidence `id`), so re-running a scan updates
  an alert instead of creating a new one.

## `report-<date>.html` — the human-readable rendering

`lib/report_html.py` renders the same object into **one self-contained HTML file** (opt in with
`REPORT=html` on a scan, or `scan.sh report` to re-render). No server, no JS, no external fetch, no
fonts, no build step — it opens offline from a USB stick, and the browser's print dialog is the PDF
story. That constraint is the feature: a security artifact you cannot open in five years is not
evidence.

It deliberately renders **more** than `kit.sarif`: every finding, including the scanner ones
carrying a triage decision, which SARIF leaves to each tool's own run. Sections: scan header (scope,
gate, dimensions with pass/fail), severity breakdown, findings table (severity + its source, tool /
rule, `file:line`, message + evidence chain, decision + confidence), then **Suppressed** on record,
then any builder warnings.

All tool- and skill-supplied text is HTML-escaped. A scanner message containing markup is data, not
markup — a security tool whose own report is injectable would be an embarrassment, so the e2e
asserts it.

## Compatibility

`schema` is versioned (`…/evidence@1`). Additive fields do not bump it; a renamed or removed field
does. A renderer must refuse a `schema` it does not recognise rather than guess.
