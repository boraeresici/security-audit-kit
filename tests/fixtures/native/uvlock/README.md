# uv.lock: what the pinned scanners see (recorded 2026-11-17)

One package with a known, fixed HIGH advisory (`urllib3==1.26.4`, CVE-2021-33503 =
GHSA-q2q7-5pp4-w6pg = PYSEC-2021-108, fixed in 1.26.5), locked with `uv lock` (uv 0.11.7), then read
by the scanners at the versions `scan.sh` pins. The manifest files carry a `.fixture` suffix so the
kit's own scans do not treat this known-vulnerable pin as the kit's dependency. Free-text advisory
fields (summaries, details, references) were stripped from the JSON; ids, aliases, packages,
versions, fixes and severities are as the tools wrote them.

| File | Tool and input |
|---|---|
| `trivy-0.58.0-uvlock.json` | `trivy fs --format json --list-all-pkgs --scanners vuln` on `uv.lock` |
| `trivy-0.58.0-requirements.json` | the same package as `requirements.txt` (control), with the kit's `--severity CRITICAL,HIGH --ignore-unfixed` |
| `osv-v2.4.0-uvlock.json` | `osv-scanner scan source -L uv.lock --format json` |
| `osv-v2.4.0-source.sarif` | `osv-scanner scan source --recursive --format sarif` over `requirements.txt` and `uv.lock` together, as `scan.sh osv` runs it (recorded 2026-11-22) |
| `trivy-0.58.0-requirements.sarif` | `trivy fs --scanners vuln --severity CRITICAL,HIGH --ignore-unfixed --format sarif` over the same directory (recorded 2026-11-22) |
| `pip-audit-2.10.1-exported.json` | `uv export --no-hashes`, then `pip-audit -r … --no-deps --disable-pip --format json` |

What it shows (F16, old plan #12):

- **trivy 0.58.0 does not read `uv.lock`.** No result, not even a package list. Given the same pin as
  `requirements.txt` it reports CVE-2021-33503 and seven more HIGH advisories. So in a uv project the
  `container` dimension says nothing about Python dependencies; `py-deps` and `osv` do.
- **The same advisory has a different id per tool.** trivy reports `CVE-2021-33503`; osv-scanner and
  pip-audit report `PYSEC-2021-108`, with the CVE and the GHSA as aliases.
- **`.trivyignore.yaml` matches trivy's own id only.** An entry for `CVE-2021-33503` removes the
  finding; one for `PYSEC-2021-108` or `GHSA-q2q7-5pp4-w6pg` does not. A suppression copied from
  pip-audit's output into `.trivyignore.yaml` suppresses nothing.

The two SARIF recordings keep rule ids, `deprecatedIds`, severities, messages and locations;
descriptions and help text were removed. What they show (F19a): osv-scanner's SARIF names the
advisory by its CVE and lists the other names in the rule's `deprecatedIds`, where its JSON output
led with `PYSEC-…`; the package and version are only in the message text; a result has no line and
appears twice per manifest; neither tool names the ecosystem. `tests/unit/test_fingerprint.py`
reads the package from both and checks that the eight advisories trivy reports get the fingerprint
osv-scanner's rows have for the same file.

Re-record when a pin changes (`TRIVY_VER`, `OSV_VER`, `PIP_AUDIT_VER`): rename the `.fixture` files
in a scratch directory, run the commands above with the pinned images, and strip the same fields.
`tests/unit/test_native_fixtures.py` pins these three facts so a pin bump that changes them fails.
