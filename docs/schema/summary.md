# `summary.json` — what each dimension did, and what the gate decided (schema 2)

> Status: **schema 2, unreleased** (F02). Schema 1 had no `schema_version` field; see *Migrating
> from schema 1* below.

`summary.json` answers *"did the scan pass, and what did it actually look at?"*. Per-finding detail
lives in [`evidence.json`](evidence.md).

- **Written by:** every `scan.sh` run, at `docs/security/scan-findings/summary.json` (a run that
  could not take the lock writes it under `runs/<run-id>/` instead).
- **Safe to parse:** written to a temp file and renamed, last in the publish step.

## Shape

```json
{
  "schema_version": 2,
  "timestamp": "2026-11-02T10:15:00",
  "run_id": "20261102T101500-4242",
  "command": "all",
  "exit_code": 1,
  "seconds": 70.5,
  "raw_log": "docs/security/scan-findings/raw-2026-11-02.log",
  "sarif": false,
  "gate": {"exit_code": 1, "blocked_by": ["sast"]},
  "provenance": {"commit": "cbf069a…", "dirty": false, "kit": {"version": "1.19.1", "checksums_sha256": "…"},
                 "config_sha256": "…", "scope": {"command": "all", "sast_paths": ".", "tf_dir": null, "base_ref": null},
                 "rules": {"semgrep_configs": "--config p/python …", "local_rules_sha256": null},
                 "tools": {"semgrep": "1.166.0", "…": "…", "gitleaks": "ghcr.io/gitleaks/gitleaks:v8.21.2@sha256:…"}},
  "artifacts": [{"path": "sarif/semgrep.sarif", "sha256": "…"}],
  "trivy_db": {"updated_at": "2026-11-03T01:30:30Z", "downloaded_at": "2026-11-03T05:44:24Z", "age_hours": 3.2, "cache": "security-audit-trivy"},
  "dimensions": [
    {"name": "secret",  "exit_code": 0, "status": "skipped",        "gate": "allow", "reason": "no docker -> gitleaks skipped"},
    {"name": "sast",    "exit_code": 1, "status": "findings",       "gate": "block", "seconds": 3.1, "reason": null},
    {"name": "py-deps", "exit_code": 3, "status": "indeterminate",  "gate": "allow", "reason": "INDETERMINATE — no project venv, ..."},
    {"name": "js-deps", "exit_code": 0, "status": "not_applicable", "gate": "allow", "reason": "no JS project"},
    {"name": "iac",     "exit_code": 0, "status": "findings",       "gate": "allow", "reason": "2 failed check(s) (soft: reported, does not block)"}
  ]
}
```

## `status` — what happened

| status | meaning | was anything inspected? |
|---|---|---|
| `pass` | the tool ran over this repo and reported nothing at the gated level | yes |
| `findings` | the tool ran and reported findings. For soft dimensions (`iac`, `container`) they are recorded but do not block | yes |
| `error` | the tool ran and **failed** (crash, bad config, scan error). Not a finding | no — treat as unknown |
| `skipped` | the dimension applies, but a tool it needs is missing (docker, uvx/pipx, a package manager) | no |
| `indeterminate` | the dimension applies but had nothing it could inspect (py-deps with no env and no static manifest) | no |
| `not_applicable` | nothing of this kind in the repo (no terraform, no JS project, no lockfiles, no changed files) | nothing to inspect |

Only `pass` and `findings` are coverage. `error`, `skipped` and `indeterminate` are unanswered
questions: never read them as clean. The run prints a `NOT inspected` line for `skipped`/`error`
and an `INDETERMINATE` line for `indeterminate`.

`reason` is the human-readable line the scan printed for that outcome, or `null`. It is prose for
people, not a stable machine key. On `pass`/`findings` it is set only when the dimension explains
its result (e.g. soft findings); an unrelated notice printed along the way is not a reason.

`seconds` (per dimension and for the whole run) is wall-clock time, to one decimal. Its resolution
depends on the shell: milliseconds with bash 5 or perl, whole seconds otherwise. It is run metadata,
so `evidence.json` does not copy it: evidence must still diff to nothing over unchanged code.

Some tools exit 1 for both "found something" and "failed" (pip-audit, gitleaks, npm/pnpm/yarn
audit, guarddog). The kit cannot tell those apart from the exit code, so they are recorded as
`findings`; the raw log has the detail. Where a tool does separate them (semgrep, zizmor,
osv-scanner, checkov, trivy, syft), `error` is used.

## `gate` — what it did to the commit

Computed separately from `status`, and unchanged by schema 2: the kit stays fail-open on missing
tools.

- Per dimension, `gate` is `block` or `allow`. Today `block` happens for `findings` from a hard
  dimension and for `error` where the gate already blocked before schema 2 (semgrep, zizmor, trivy,
  syft, a refused `OSV_CALL_ANALYSIS=rust`). An osv-scanner scan error and a checkov crash stay
  `allow`, as before.
- Top-level `gate.exit_code` is the scan's exit code (also kept as `exit_code` for schema 1
  readers) and `gate.blocked_by` lists the dimensions with `gate: "block"`.

`exit_code` per dimension is the kit's internal code (`0`, `1`, `3`, or the tool's own non-zero
code on failure). Prefer `status` and `gate`; `exit_code` is kept for compatibility.

## `provenance` — what was scanned, with what (F03)

Taken at the start of the run, before any dimension runs (sbom writes into the tree and would
otherwise make every run look dirty). It describes content, not the run: no time, no run id. That
is why `evidence.json` can carry it verbatim and stay diffable.

| field | meaning |
|---|---|
| `commit` | `HEAD` at scan time; `null` in a repo with no commits |
| `dirty` | uncommitted changes (tracked or untracked) outside `docs/security/scan-findings/`; `null` with no commit. A dirty scan describes the working tree, not `commit` |
| `kit.version` | the vendored `.kit-version` ref, else the newest released CHANGELOG version |
| `kit.checksums_sha256` | digest of the kit's `CHECKSUMS` — identifies the exact kit files, rules included |
| `config_sha256` | digest of `.security-audit.conf` (or `SECURITY_AUDIT_CONF`); `null` without one |
| `scope` | the command and the knobs that narrow it: `SAST_PATHS`, `TF_DIR`, `BASE_REF` |
| `rules` | the semgrep config set, and one digest over the repo's local rule files (`null` with none) |
| `tools` | every pinned tool: a version for the uvx tools, `image:tag@digest` for the docker ones |

Digests are `null` when the machine has no sha256 tool.

When the `container` dimension ran, `provenance.trivy_db.updated_at` names the vulnerability DB it
used (F30). That is the DB's identity: the same DB always gives the same value, so it can be part of
`evidence.json`. Its **age** is run metadata and goes only into the top-level `trivy_db` object
(`updated_at`, `downloaded_at`, `age_hours`, `cache`; `null` when trivy did not run). A "clean" from
a 20-hour-old DB and one from a fresh DB can be told apart there.

## `artifacts` — what this run produced

The SARIF files this run wrote, each with its sha256 (empty unless `SARIF=1`). `evidence.json` is
built only from these, and only for dimensions whose status is `pass` or `findings`. Since F03 the
shared `sarif/` directory holds exactly this run's files: an earlier run's SARIF is removed when a
`SARIF=1` run publishes, so it cannot be uploaded or read as a current result. A `SARIF=0` run
leaves `sarif/` and `evidence.json` as they were; their `provenance` says which commit they
describe.

## Versioning

`schema_version` changes only on a breaking change; new fields are added without a bump, so readers
must ignore fields they do not know. summary.json is rewritten by every scan and never migrated in
place. Policy: [RELEASING.md](../../RELEASING.md#upgrade-notes-deprecation-and-schema-versions).

## Migrating from schema 1

Schema 1 had no `schema_version`, no top-level `gate`, and per dimension only
`name`, `exit_code` and `status` ∈ `pass | fail | indeterminate`.

- `"fail"` is gone. It is now `findings` or `error`; check `gate == "block"` if what you meant was
  "this dimension blocked".
- `"pass"` no longer covers dimensions that never ran. A consumer that treated `pass` as clean now
  also sees `skipped`, `error` and `not_applicable` for those; treat the first two as not clean.
- A soft dimension with findings (`iac`, `container`) used to be `pass`; it is now `findings` with
  `gate: "allow"`.
- New fields are additive: `schema_version`, `gate`, `provenance`, `artifacts`, and per dimension
  `gate` and `reason`.
- Branch on `schema_version` (absent = 1).
