# What leaves the machine — data flow per command (F13)

The kit runs on your machine. It has no server, no account and no telemetry of its own. That is not
the same as "nothing leaves your machine". Several scanners look things up on the internet, and the
AI layer runs inside your coding agent, which sends what it reads to its model provider. This page
lists, per command, what runs locally, what needs the network, and what kind of data goes where.

**How this was established:** by reading the kit's code and the tools' documented behaviour (a
code / tool-contract review). No network traffic was captured. If a tool changes what it sends,
this page can lag behind; the pins (`.kit-version`, image digests, exact tool versions) limit that
to kit updates.

Three different things, kept apart:
- **Runs locally:** the analysis happens on your machine.
- **Needs the network:** something is downloaded (a tool, a rule pack, a vulnerability DB).
- **Sends data about your repo:** something derived from your repo leaves the machine. This is the
  one that matters, and the table names exactly what.

## Per command

| Command / layer | Runs locally | Network: downloads | Sends data about your repo |
|---|---|---|---|
| `bootstrap.sh` | yes | the kit from its git repo (`KIT_REPO`) | nothing (a `git ls-remote` / clone of the kit) |
| first run of any `uvx` tool | — | the pinned tool from PyPI | nothing |
| first run of any Docker dimension, `warm` | — | pinned images by digest (ghcr.io, Docker Hub) | nothing |
| `secret`, `staged` (gitleaks) | yes | image only | **nothing** |
| `sast`, `changed` (semgrep) | yes | `p/...` rule packs from the semgrep registry, each run | the **names of the rule packs** requested (they reflect your detected stack). Source code: no. Metrics are off (`--metrics off`) |
| `py-deps` (pip-audit) | yes | — | **package names and versions** of the environment, to PyPI's advisory API |
| `py-deps` without a venv (osv-scanner) | yes | image only | **package names and versions** from the committed manifests, to osv.dev |
| `js-deps` (npm / pnpm / yarn audit) | yes | — | the **dependency tree** (names and versions from the lockfile) to the package registry's audit endpoint |
| `edit` (the plugin's hook, after each agent edit; semgrep on one file) | yes | `p/...` rule packs from the semgrep registry, each run | the **names of the rule packs** requested, as for `sast`. Source code: no |
| `iac` (checkov) | yes | — | nothing. The kit sets no platform API key, so nothing is uploaded |
| `container` (trivy) | yes | the vulnerability DB (ghcr.io), when older than `TRIVY_DB_MAX_AGE_H`. `SCAN_OFFLINE=1`: never | nothing |
| `sbom` (syft) | yes | image only | nothing |
| `osv` (osv-scanner) | yes | image only | **package names and versions** (all ecosystems) to osv.dev |
| `guarddog` | yes | **every declared dependency's package** from PyPI / npm, to analyse it | the **list of your dependencies**, as download requests |
| `pkgcheck` (and the opt-in agent hook) | yes | the named package from PyPI / npm | the **package name** being installed |
| `zizmor` | yes, `--offline` | — | nothing |
| `verify`, `doctor`, `allowlist`, `evidence`, `report`, `rules-test` | yes | — | nothing |
| HTML report (`REPORT=html`, `scan.sh report`) | yes | — | nothing: one self-contained file, no scripts, no external fetch, opens offline |
| AI layer (`/sec-triage`, `/sec-audit`, other skills) | **no** | — | **what the agent reads**: source files, findings, config, scan output. It goes to the model provider your coding agent uses, under that provider's terms. The kit does not control this, and it is the largest flow by far |

**What `all` sends**, in short: rule-pack names (semgrep), your Python and JS dependency names and
versions (pip-audit, the JS audit), and a vulnerability DB download (trivy). Source code is not
sent by any scanner.

## Fully offline

Everything except the dependency lookups can run without a network once its tools are cached:
1. Run `scan.sh warm` while online (images and the trivy DB).
2. Run the scans with `SCAN_OFFLINE=1`: trivy then uses the cached DB at any age.

The dependency dimensions (`py-deps`, `js-deps`, `osv`, `guarddog`, `pkgcheck`) cannot work
offline. Without the network they cannot return a clean result: they fail, or say they did not
inspect anything.

semgrep's registry packs are fetched each run. For an offline SAST run, set
`SEMGREP_CONFIGS="--config <local rule file or dir>"`; it replaces the registry packs.

## Related
- [threat-model.md](threat-model.md), row 10: "Data leaves the machine".
- [SECURITY.md](../SECURITY.md): trust model and reporting.
