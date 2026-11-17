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

Re-record when a pin changes (`TRIVY_VER`, `OSV_VER`, `PIP_AUDIT_VER`): rename the `.fixture` files
in a scratch directory, run the commands above with the pinned images, and strip the same fields.
`tests/unit/test_native_fixtures.py` pins these three facts so a pin bump that changes them fails.
