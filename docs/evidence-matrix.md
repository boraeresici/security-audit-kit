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
| `py-deps` (project venv) | pip-audit `--strict` | log only | no | — | `.pip-audit-ignore` (`--ignore-vuln`) | not in the output |
| `py-deps` (no venv) | osv-scanner `-L` on lockfiles | log only | no | — | `osv-scanner.toml` | not in the output |
| `js-deps` | pnpm / yarn / npm `audit` | log only | no | — | none in the kit | — |
| `iac` | checkov `--soft-fail` | log only (failed count read from it) | no | — | `#checkov:skip=` | not in the output |
| `container` | trivy `fs` (vuln, secret, misconfig, license) | `trivy.sarif` | **yes** | `security-severity` (CVSS) | `.trivyignore.yaml`, trivy's own ids only | not in the output (measured, 0.58.0) |
| `sbom` | syft | CycloneDX + SPDX JSON | artifact, no findings | — | — | — |
| `osv` | osv-scanner `scan source` | `osv.sarif` | **yes** | `security-severity` | `osv-scanner.toml` | not in the output (not measured) |
| `guarddog` | guarddog `verify` | log only | no | — | none in the kit | — |
| `zizmor` | zizmor `--offline` | `zizmor.sarif` | **yes** | SARIF `level` | `# zizmor: ignore[…]` | not measured |
| judgment | the skills' `findings-<date>.md` | markdown table | **yes**, `dimension: judgment` | the skill's rating, [F39 scale](skills.md#severity-of-a-judgment-finding) | `### Suppressed` section | recorded as **suppressed** |

"Measured" means run against the pinned version and recorded; the rest is read from `scan.sh` and
`lib/evidence.py`. e2e checks that every unit in the registry has a row here and that the units
marked **yes** are exactly the ones `lib/evidence.py` reads SARIF for.

## Known gaps, in the order they close (F16b)

- **No rows for pip-audit, the JS audits, checkov and guarddog.** Each gets an adapter that reads the
  tool's native JSON and normalises it in `lib/`, keeping package, version and aliases. Until alias
  deduplication exists, their rows go to `evidence.json` and the report, not to Code Scanning.
- **One advisory, three ids.** trivy reports `CVE-2021-33503` where osv-scanner and pip-audit report
  `PYSEC-2021-108`, and `.trivyignore.yaml` matches trivy's own id only
  ([recording](../tests/fixtures/native/uvlock/README.md)). `scan.sh allowlist` compares ids
  literally until F19's alias map exists.
- **trivy 0.58.0 does not read `uv.lock`.** In a uv project, `container` says nothing about Python
  dependencies; `py-deps` and `osv` do.
- **A severity the tool does not give** (pip-audit, checkov without a platform key) will be
  `unknown` with `severity_source: "<tool>:none"`, not a guess.
