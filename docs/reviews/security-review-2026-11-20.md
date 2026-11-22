# Security review of the kit itself — 2026-11-20 (fixed in 1.22)

The kit was reviewed as a target: can a branch, a dependency or repo text run code through it, or
switch it off? Scope: v1.21.0 plus Unreleased. Everything below was reproduced on throwaway repos
before it was fixed, and each fix has a regression case in `tests/trust-gate.sh` (48 cases, offline,
in CI on Linux and macOS).

## How it was done

- **Mapping:** cheaper models read the code and the planning documents and produced indexes with
  `file:line` references (Claude Haiku for documents and the Python layer, Claude Sonnet for
  `scan.sh`, the hooks, the skills and the eval harness).
- **Verification and assessment:** Claude Fable 5.2 checked every candidate finding against the
  source, reproduced it, searched for further issues and reviewed the roadmap. A second, separate
  Fable 5.2 pass cross-checked the finished branch and found the residuals listed at the end.
- **Main session:** Claude Opus 5.5 re-read the critical lines, wrote the fixes test-first and ran
  the suites.
- Not used: Claude Mythos. Not run: docker-backed dimensions (no daemon in the review environment),
  yarn berry and corepack (shims only), the provider evals. Model names are recorded for
  transparency; they are not a claim of assurance. The evidence is the tests.

## Findings and fixes

| ID | Finding | Severity | Fix (1.22) |
|---|---|---|---|
| N1 | `core.hooksPath` pointed into the vendored tree: a branch's `hooks/post-checkout` ran on `git checkout`; an edited hook ran on commit | Critical | Hooks are wrappers in `.git/security-audit-hooks/`; each checks the kit against the manifest recorded in `.git` at install before running it |
| A | `.security-audit.conf` was sourced before every command: `exit 0` defeated `verify`, `SKIP_SECURITY=1` turned the gate off for the team | High | Parsed as data, never sourced; known names, literal values; switches and tool pins are environment-only |
| C | `verify` looked for extra files under `skills/` only, by substring; a regenerated `CHECKSUMS` passed | High | Every file and link of the kit, exact match; the hooks also hold `CHECKSUMS` to the install anchor |
| B | Python helpers ran with the repo root on `sys.path`: a repo `json.py` was imported | High | `-I` for stdin / `-c` helpers; no bytecode read or written beside the kit's sources |
| N2 | pip-audit ran a committed `.venv/bin/python` | High | A venv with tracked files, or without `pyvenv.cfg`, is not used (also for `PY_VENV`) |
| N3 | A repo `.checkov.yaml` made checkov import repo Python and report `iac pass` | High | The kit's own empty `--external-checks-dir`; `external-checks-git` means checkov is not run |
| I | js-deps ran repo JavaScript (`.pnpmfile.cjs`, yarn `yarn-path`); a repo `.npmrc` registry turned a vulnerable lockfile into a pass | High | Forced registry (environment only), pnpmfile and yarn-path ignored, yarn not run when `.yarnrc.yml` loads repo code |
| N4 | The config check said "settings only, all known" for `SARIF=0 touch x` | Medium | Gone with the data parser |
| G | sec-triage accepted a comment or a `tests/` path as false-positive evidence and wrote allowlists and the config on its own | High | Suppressions are proposed and written only after the user confirms; the config is never written; comments and paths are not evidence by themselves; an exclusion added in the range under review is not applied |
| F | Allowlists and scanner configs added in the same change suppressed silently | Medium | `policy_changes` in `summary.json` and a `── policy:` line on every run |
| E | An osv-scanner crash allowed the push; a skipped dimension never blocked | Medium | An osv crash blocks; `GATE_STRICT=1` blocks on anything not inspected; zizmor is in `all` |
| — | `bootstrap.sh --expect` was a prefix match | Low | Full commit id only |

Residuals found by the cross-check of the branch, fixed before release: linked worktrees falsely
blocked; an unchecked-hash `.pyc` under `lib/__pycache__` excluded from the check yet executable;
`PY_VENV` skipping the tracked-venv check; tool pins readable from the config; scanner flags
smuggled through list values; case-sensitive suppression markers.

## Open, by design or later

The bypasses that remain by design (`--no-verify`, `SKIP_SECURITY=1` in the environment, reviewed
allowlist entries) and what shows each one are listed in [docs/threat-model.md](../threat-model.md).
Still open: measuring the judgment skills against prompt injection on the shipped backend (1.23),
and a CI verifier template for teams.
