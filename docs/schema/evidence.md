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
5. **Only what this run produced.** A file on disk proves nothing about when it was written, so
   findings come only from the SARIF files listed in `summary.json` `artifacts` (this run's output,
   with sha256), and only for dimensions whose status is `pass` or `findings`. A skipped or crashed
   dimension's output, a file changed after the scan (sha256 mismatch), a listed file that is
   missing, and any SARIF file not in the list are all left out, each with a line in `warnings`
   (also printed by the builder). A summary written before schema 2 has no `artifacts`: then the
   files of the dimensions it lists are used, with a warning that nothing proves they belong to that
   run. With no `summary.json` at all, everything is included and a warning is recorded.
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
    "dimensions": [{"name": "sast", "exit_code": 0, "status": "pass", "gate": "allow", "reason": null}]
    // Copied from summary.json, minus the per-run `seconds` — see docs/schema/summary.md. From summary schema 2,
    // status is "pass" | "findings" | "error" | "skipped" | "indeterminate" | "not_applicable";
    // only "pass" and "findings" mean the dimension inspected something. Schema 1 summaries
    // (status "pass" | "fail" | "indeterminate") are still accepted and copied as they are.
    "provenance": {"commit": "…", "dirty": false, "kit": {"version": "1.20.0"}, "…": "…"}
    // Copied from summary.json when present: WHAT was scanned, with what (commit, dirty tree, kit,
    // config, rules, tool pins, scope). It carries no time and no run id, so rule 4 still holds;
    // run metadata stays in summary.json. Fields: docs/schema/summary.md#provenance.
    "artifacts": [{"path": "sarif/semgrep.sarif", "sha256": "…"}]
    // Also copied from summary.json: the SARIF list this evidence was built against.
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
| `id` | string | 12-hex `sha1(dimension\|rule_id\|file\|line)`. Survives a re-scan of unchanged code, but not a line shift: use `fingerprint` to follow a finding over time. Kept for this version beside it. |
| `fingerprint` | string | 20-hex identity that survives what does not change the finding (F19a). What a decision record keys on. See [Fingerprint](#fingerprint). |
| `fingerprint_basis` | enum | `line-content` · `package` · `location`: what the fingerprint was computed from, so a reader knows how much a match means. |
| `dimension` | string | `secret` · `sast` · `container` · `osv` · `zizmor` — the `scan.sh` dimension that produced it. |
| `tool` | string | `gitleaks` · `semgrep` · `trivy` · `osv-scanner` · `zizmor`. |
| `rule_id` | string | The tool's rule / check id, verbatim. |
| `file` | string | Repo-relative path. |
| `line` | int\|null | 1-indexed start line; `null` when the tool reports no location. |
| `message` | string | The tool's message, single-line, trimmed. |
| `severity` | enum | Normalized: `critical` · `high` · `medium` · `low` · `unknown` · `info`. `unknown`: the tool gave none (pip-audit), never guessed or folded into `info`. |
| `severity_source` | string | The tool's own value, verbatim, e.g. `semgrep:level=error`, `trivy:security-severity=8.8`. |
| `cvss` | float\|null | Passthrough **only** where the tool supplied a CVSS-derived score. |
| `decision` | enum\|null | `real` · `fp` · `uncertain` · `suppressed` · `null` (not yet judged). Written by the judgment layer, not the scan. |
| `confidence` | float\|null | 0–1, from the triage confidence gate. |
| `evidence` | object\|null | The claim → location chain: `{"sink": "path:line", "source": "…", "note": "…"}`. |
| `review` | object (optional) | A person's decision from `docs/security/decisions.json`, present only when there is one. Display only; never changes the gate. See [decisions.md](decisions.md#shown-on-the-finding). |

The scan fills everything down to `cvss`; `decision` / `confidence` / `evidence` stay `null` until a
judgment pass (`/sec-triage`) fills them. A renderer must treat `null` as *undecided*, never as *FP*.

## Fingerprint

`id` contains the line number, so one line inserted above a finding makes it a new finding and a
decision about it is lost. `fingerprint` is the identity that follows the finding instead
(`lib/fingerprint.py`). Which of three bases applies is recorded in `fingerprint_basis`:

| Basis | For | Computed from | Survives | Does not survive |
|---|---|---|---|---|
| `line-content` | a finding with a file and a line the kit can read | dimension, rule, file, the reported line with whitespace collapsed, and which occurrence of that text this is among the rule's findings in the file | lines moving, re-indentation | an edit to the line, a file rename |
| `package` | a row with `package` (pip-audit, npm audit, guarddog; osv-scanner and trivy dependency rows) | advisory under its canonical name, ecosystem, package name, manifest | a version bump, a move within the lock file | another package, another manifest |
| `location` | everything else | dimension, rule, file, line (the inputs of `id`) | a re-scan of unchanged code | a line shift |

- **The version is not part of a package fingerprint.** A bump that does not fix the advisory is the
  same finding; one that fixes it makes the row go away. Two packages with one advisory in one
  manifest are two findings. PyPI names are compared as PEP 503 normalises them; other ecosystems
  as written. pip-audit audits an environment, not a manifest, so its rows use the fixed manifest
  `python-env`: a venv's path differs per machine and would make the identity local.
- **The same line twice.** Two identical lines flagged by one rule in one file are two findings,
  numbered in line order (GitHub code scanning's method for `primaryLocationLineHash`). Removing
  the first one makes the second take its fingerprint; that ambiguity is inherent to the method.
- **Secret findings always use `location`.** The reported line is the secret, and a hash of it in
  a report that is mailed around could confirm a guess of a weak one offline.
- **The line is read from the working tree**, only for a repo-relative path with no `..` that
  resolves inside the repo to a regular file of at most 5 MiB. Anything else (a link out of the
  repo, a file that is gone, a line past the end, a blank line) falls back to `location`.
- **One advisory, several names.** `PYSEC-2021-108`, `CVE-2021-33503` and `GHSA-q2q7-5pp4-w6pg` are
  one advisory. The fingerprint uses one name, chosen from the row's own `rule_id` and `aliases`:
  the CVE if there is one, else the GHSA, else the first id in sort order. Only the row's own
  names count, never what another tool said in the same run, so a fingerprint does not change
  with the set of dimensions that ran. A tool that gives no aliases (trivy) meets another only
  when its id is already that name; rows that do not meet stay two findings, which costs a
  second decision and never hides one. An advisory that gets its CVE later changes fingerprint.
- **osv-scanner and trivy dependency rows carry `package` too.** Their SARIF has it only in the
  message text (`Package 'urllib3@1.26.4' is vulnerable to …`; `Package: urllib3` / `Installed
  Version: 1.26.4`), read in the shapes recorded from the pinned tools
  (`tests/fixtures/native/uvlock/*.sarif`). osv-scanner's rule lists the aliases (`deprecatedIds`),
  trivy's message the fixed versions. Neither names the ecosystem: it is taken from the manifest's
  file name (`requirements*.txt`, `uv.lock`, `package-lock.json`, `go.sum`, …) and left empty when
  the name does not say. A message in another shape adds nothing and the row keeps `line-content`.
- **The same fingerprint on two rows** is the same finding reported by two tools (osv-scanner and
  trivy over one `requirements.txt`). The rows are not merged: each keeps its tool's severity and
  message, and one decision will cover both. The same advisory in two manifests is two findings.
- **Decisions key on it.** A person's decision is recorded by fingerprint in
  `docs/security/decisions.json` with `scan.sh decide` ([decisions.md](decisions.md)), and shown on
  the finding as `review`, with `counts.by_review`.

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

pnpm and yarn audits write no per-finding output the kit reads yet, so they appear in `scan.dimensions` with a status but contribute no `findings`
entries; `warnings` names each one that had findings, and the report header says so. Their findings
reach a human through `raw-<date>.log` and triage. The per-unit picture, and the adapters that close
this, are in the [evidence matrix](../evidence-matrix.md).

**Dependency rows from native JSON (F16b).** pip-audit writes JSON, not SARIF (`pip-audit.native.json`,
listed in the run's `artifacts` like a SARIF file); `lib/native.py` turns it into rows with
`file`/`line` null and three more fields: `package` (`{ecosystem, name, version}`), `aliases` (the
advisory's other ids) and `fixed_in`. The `id` hashes dimension, advisory and package name, so the same
advisory in two packages is two findings, and a version change keeps the id.

**checkov rows (F16b).** With `SARIF=1` checkov also writes `checkov.native.json`; each failed check
is a row with the repo-relative `file` and first `line` of the resource, plus `resource` and
`guideline`. A check skipped with `#checkov:skip=<id>:<reason>` is a row with `decision: "suppressed"`
and the reason in `evidence.note`. checkov gives no severity without a platform key: `unknown`.

**guarddog rows (F16b).** With `SARIF=1` each `guarddog <eco> verify <manifest>` run is kept in
`guarddog.native.json` with the packages the manifest asked for. Each package and fired rule is a row,
except `capability-*` rules (what a package can do, which fire on `requests`); `file` is the
manifest, `package` names it, `detail` holds guarddog's first location or message, and the severity is
guarddog's own from its `risks`, else `unknown`. A requested package guarddog returned nothing for,
and a rule that did not run, are in `warnings`.

**npm audit rows (F16b).** With `SARIF=1` each JS project audited with npm keeps its
`npm audit --json` report (auditReportVersion 2) in `npm-audit.native.json`. Each package and
advisory is a row: `rule_id` is the GHSA id (else `npm-<source>`), `file` the project's
`package-lock.json`, the severity npm's own (`moderate` is `medium`), `cvss` the advisory's score,
which comes from the GitHub advisory, plus `affected`, `direct` and `fixed_in`. A package listed only
because it depends on a vulnerable one is not a row. pnpm and yarn reports are not read yet.

A finding the tool itself marked as suppressed in its SARIF (semgrep's `# nosemgrep`, written with
`suppressions: [{kind: inSource}]`) is recorded with `decision: "suppressed"` and the tool's note, so
it is on record and not counted as reported. A suppression whose `status` is `rejected` or
`underReview` leaves the finding live.

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
- **The table is untrusted input.** A model that read the scanned repo writes it, and its location
  ends up in `kit.sarif`, which Code Scanning ingests. A row is dropped, with a warning that quotes
  it escaped, unless its location is a repo-relative path of at most 1024 characters: no leading
  `/` or `~`, no colon (a URI scheme or drive letter), no backslash; no empty, `.` or `..` segment,
  and none that starts with a space or ends with a dot or a space; no control, format, separator,
  private-use or unassigned character, no space other than U+0020, and nothing that compatibility
  normalization would turn into something else (fullwidth `．．`). A leading `./` is removed first;
  `path:line:column` keeps the line. A line, if given, is 1 to 10,000,000. The first 20 dropped
  rows are named, the rest counted. `kit.sarif` percent-encodes the path, so `%`, `?`, `#` and
  spaces in a file name stay part of the name.
- **Free-text cells** lose control characters, bidirectional controls, zero-width spaces and tag
  characters (joiners that belong to the text, as in emoji or Persian, stay) and are cut at 2000
  characters; the severity cell at 40. A confidence outside `[0, 1]`, `nan` and `inf` included,
  becomes `null` with a warning. A `[text](url)` link in the message reaches `kit.sarif` broken
  apart. A findings file over 2 MiB, or one that is not UTF-8, skips the judgment layer with a
  warning; a UTF-8 BOM is accepted.
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
- Results carry `partialFingerprints.sakFindingId` (the evidence `id`). GitHub does not match alerts
  on it: Code Scanning uses only `primaryLocationLineHash`, which `upload-sarif` computes from the
  source when the file does not carry one. The kit's id changes when a finding moves to another
  line (it hashes the line number, F19), so it is a stable key for the kit's own records within one
  version of the code, not across edits.

## `report-<date>.html` — the human-readable rendering

`lib/report_html.py` renders the same object into **one self-contained HTML file** (opt in with
`REPORT=html` on a scan, or `scan.sh report` to re-render). No server, no JS, no external fetch, no
fonts, no build step — it opens offline from a USB stick, and the browser's print dialog is the PDF
story. That constraint is the feature: a security artifact you cannot open in five years is not
evidence.

It deliberately renders **more** than `kit.sarif`: every finding, including the scanner ones
carrying a triage decision, which SARIF leaves to each tool's own run. Sections: scan header (scope,
gate, one chip per dimension with its status and, on hover, its reason), severity breakdown, findings table (severity + its source, tool /
rule, `file:line`, message + evidence chain, decision + confidence), then **Suppressed** on record,
then any builder warnings.

**The header says only what it can vouch for (F04).** Its *Result* line is one of:

| result | when |
|---|---|
| `clean (exit 0)` | the gate passed, every dimension that applies inspected something, and nothing is reported |
| `passed (exit 0) — N finding(s) present, none blocking` | soft findings (`iac`, `container`) or reported findings that did not block |
| `passed (exit 0) — NOT complete: <dim> (<status>) …` | a dimension was `skipped`, `error` or `indeterminate`, or no dimensions were recorded |
| `blocked (exit N): <dim> (findings) / <dim> (scan error, not a finding)` | the gate blocked; a crashed tool is named as such |
| `indeterminate (exit 3)` / `unknown` | nothing could be inspected, or no exit code was recorded at all |

The scan time and the report date are shown separately. `evidence.json` carries no time, so the
scan time comes from `summary.json`, and only when that summary is the evidence's own run (same
`dimensions`, `artifacts` and `provenance`; `scan.artifacts` is copied into evidence for this). A
`SARIF=0` run publishes a new summary but leaves evidence alone, so a later re-render says
*scan time unknown* instead of borrowing that run's time.

**Exit status.** `scan.sh evidence` and `scan.sh report` exit 1 when they cannot produce their file:
no python3, a missing lib, no SARIF, no `evidence.json`, a builder failure or a `kit.sarif` that
could not be written. After a scan (`SARIF=1`, `REPORT=html`), the same failure is printed with
*"the gate result is unchanged"*. The scan's exit code is the scanners' verdict, and a report that
could not be rendered does not change what they found.

All tool- and skill-supplied text is HTML-escaped. A scanner message containing markup is data, not
markup — a security tool whose own report is injectable would be an embarrassment, so the e2e
asserts it.

## Versioning

The `schema` tag (`security-audit-kit/evidence@1`) changes only on a breaking change. New fields are
added without a bump (`scan.provenance`, `scan.artifacts` were), so readers must ignore fields they
do not know. evidence.json is rebuilt on every `SARIF=1` scan and never migrated in place. After an
update that bumps the tag, the next scan writes the new version, and `report_html.py` refuses a tag
it does not know instead of misreading it. Policy: [RELEASING.md](../../RELEASING.md#upgrade-notes-deprecation-and-schema-versions).

## Compatibility

`schema` is versioned (`…/evidence@1`). Additive fields do not bump it; a renamed or removed field
does. A renderer must refuse a `schema` it does not recognise rather than guess.
