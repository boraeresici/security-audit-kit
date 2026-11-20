# Evidence matrix — what each dimension leaves behind

For every scan unit: the tool, what it writes, whether its findings reach `evidence.json` (and from
there the HTML report and the SARIF a CI job can upload), where a severity comes from, and what
happens to a finding someone suppressed. Start with the [README](../README.md); the record formats
are in [`summary.json`](schema/summary.md) and [`evidence.json`](schema/evidence.md), the adapter
contract in [adapters](adapters.md).

**A dimension without rows is not a clean dimension.** Its status in `summary.json` still says
`findings` when the tool found something; the report names it in the header ("findings in iac, not
listed below"), and `evidence.json` carries a warning for it. The findings themselves are in
`raw-<date>.log`.

| Unit | Tool | Native output | Rows in `evidence.json` | Severity from | Suppress with | A suppressed finding |
|---|---|---|---|---|---|---|
| `secret` | gitleaks `detect` (full history) | `gitleaks.sarif` | **yes** | the tool's default (high) | `.gitleaks.toml` allowlist, `gitleaks:allow` | not in the output (not measured) |
| `staged` | gitleaks `protect --staged` | log only | no | — | same as `secret` | not in the output |
| `sast` | semgrep, `--severity ERROR` | `semgrep.sarif` | **yes** | SARIF `level` | `# nosemgrep` | in the SARIF with `suppressions`; recorded as **suppressed** (measured, 1.166.0) |
| `sast-changed` | semgrep on changed files | `semgrep.sarif` | **yes**, as `sast` | SARIF `level` | `# nosemgrep` | as `sast` |
| `py-deps` (project venv) | pip-audit `--strict` | `pip-audit.native.json` (with `SARIF=1`) | **yes**, via `lib/native.py` | none from the tool: `unknown` | `.pip-audit-ignore` (`--ignore-vuln`) | not in the output |
| `py-deps` (no venv) | osv-scanner `-L` on lockfiles | log only | no | — | `osv-scanner.toml` | not in the output |
| `js-deps` | pnpm / yarn / npm `audit` | log only | no | — | none in the kit | — |
| `iac` | checkov `--soft-fail` | `checkov.native.json` (with `SARIF=1`); the table stays in the log | **yes**, via `lib/native.py` | checkov's, if any; without a platform key `unknown` | `#checkov:skip=` | in the JSON with its reason; recorded as **suppressed** (measured, 3.3.1) |
| `container` | trivy `fs` (vuln, secret, misconfig, license) | `trivy.sarif` | **yes** | `security-severity` (CVSS) | `.trivyignore.yaml`, trivy's own ids only | not in the output (measured, 0.58.0) |
| `sbom` | syft | CycloneDX + SPDX JSON | artifact, no findings | — | — | — |
| `osv` | osv-scanner `scan source` | `osv.sarif` | **yes** | `security-severity` | `osv-scanner.toml` | not in the output (not measured) |
| `guarddog` | guarddog `verify` (pypi and npm) | `guarddog.native.json` (with `SARIF=1`): each run plus the packages the manifest asked for | **yes**, via `lib/native.py`; `capability-*` rules are not rows | guarddog's own, from `risks`; else `unknown` | none in the kit | — |
| `zizmor` | zizmor `--offline` | `zizmor.sarif` | **yes** | SARIF `level` | `# zizmor: ignore[…]` | not measured |
| judgment | the skills' `findings-<date>.md` | markdown table | **yes**, `dimension: judgment` | the skill's rating, [F39 scale](skills.md#severity-of-a-judgment-finding) | `### Suppressed` section | recorded as **suppressed** |

"Measured" means run against the pinned version and recorded; the rest is read from `scan.sh` and
`lib/evidence.py`. e2e checks that every unit in the registry has a row here and that the units
marked **yes** are exactly the ones whose output (SARIF or native JSON) `lib/evidence.py` reads.

## Known gaps, in the order they close (F16b)

- **No rows for the JS audits.** Each gets an adapter that reads the tool's
  native JSON and normalises it in `lib/native.py`, keeping package, version and aliases, as
  pip-audit's, checkov's and guarddog's do now. These rows go to `evidence.json` and the report, not to Code Scanning: the
  native files are not SARIF, and a CI job uploads `sarif/*.sarif`.
- **One advisory, three ids.** trivy reports `CVE-2021-33503` where osv-scanner and pip-audit report
  `PYSEC-2021-108`, and `.trivyignore.yaml` matches trivy's own id only
  ([recording](../tests/fixtures/native/uvlock/README.md)). `scan.sh allowlist` compares ids
  literally until F19's alias map exists.
- **trivy 0.58.0 does not read `uv.lock`.** In a uv project, `container` says nothing about Python
  dependencies; `py-deps` and `osv` do.
- **guarddog drops a package it cannot fetch** and still exits 0 (measured, 3.0.2). The record keeps
  the packages each manifest asked for, so `evidence.json` names the ones guarddog returned nothing
  for. A rule that fails (a timeout, seen live) is named; the other rules' results stay.
- **guarddog's exit code counts capabilities**, so it is not the verdict. `requests` alone makes
  `guarddog verify --exit-non-zero-on-finding` exit 1 with no threat rule fired (label
  `no_risks_detected`). The `guarddog` dimension now decides from what fired: a rule on `pkgcheck`'s
  measured block list blocks, any other threat or metadata rule is reported, not blocking.
- **A severity the tool does not give** is `unknown`, with `severity_source: "<tool>:none"`, not a
  guess: pip-audit gives none, and checkov gives none without a platform key.
- **pip-audit repeats advisories.** 2.10.1 lists most of them twice per package (43 entries for 23
  advisories, measured); the adapter keeps one row per package and advisory, and the scan log says
  how many entries pip-audit listed.
