# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - Unreleased

### Added — triage v2 (higher signal, less noise)
- `.security-exclusions.md` (template `exclusions.example.md`, installed by `install.sh`): a
  per-project list of do-not-report classes + precedent assumptions the triage skills read first.
- **Confidence-scored verification pass** in `sec-triage`: every surviving finding is judged
  independently with a `[0,1]` confidence; only ≥ 0.7 is reported, the rest go to a "Suppressed"
  section (on record, not silently dropped). New confidence column in the findings template.
- **Reachability / attacker-control gate** across `sec-triage` and `sec-sast-deep`: a finding not
  reachable from untrusted input is dropped as FP.
- **`tests/e2e.sh`** — end-to-end local test: vendors the working tree into a throwaway repo,
  runs `install.sh`, and asserts each gate fires (install/hooks/skills/config, secret + pre-commit
  gate, SAST via a fixture rule, summary.json). Tests the scriptable plumbing, not AI judgment.
- **Supply-chain integrity (Tier S Layer 2):** a `CHECKSUMS` manifest + `scan.sh verify` (detects
  tampered files / a rogue skill in a vendored copy) + `scan.sh checksums` to (re)generate it.
  `install.sh` runs verify (advisory); CI fails if the manifest is stale.

### Changed
- `sec-sast-deep` reframed as an explicit 3-phase **baseline → compare → assess** flow (map the
  project's known-correct patterns, flag deviations, then assess) + the reachability + confidence
  gates and a Suppressed sub-list.
- `sec-ai-review` gains the exclusions read + confidence gate (its data/authority flow already is
  the reachability gate).

## [1.2.0] - 2026-06-16

### Added
- `sec-ai-review` skill — semantic AI/LLM security review mapped to the OWASP LLM Top 10
  (prompt injection, insecure output handling, excessive agency, disclosure, supply chain).
  Sourced from `utkusen/awesome-ai-security`. Installed into `.claude/skills/` like the others.
- `scan.sh changed` — diff-aware SAST that runs semgrep only on files changed vs a base
  (`$BASE_REF`, else merge-base with `origin/main`, else staged + unstaged).
- Status badges in the README (ci, self-audit, license, release).
- `self-audit` workflow (dogfooding): the kit runs its own `secret` + `sast` scans on this
  repo and uploads SARIF to GitHub code scanning; weekly schedule + on push/PR.

### Changed
- Skill source templates moved from the repo root into `skills/` (organizational only; they
  are still installed into the target repo's `.claude/skills/<name>/SKILL.md`).
- CI split: `ci.yml` is shellcheck-only; the self-scan moved to `self-audit.yml`.
- Bumped `actions/checkout` v4 → v5.

## [1.1.0] - 2026-06-16

### Added
- `scan.sh staged` — sub-second secret scan of staged changes (`gitleaks protect --staged`).
- `scan.sh doctor` — reports toolchain availability, resolved pins, and detected projects.
- `summary.json` — every scan writes a machine-readable summary alongside the raw log.
- Optional SARIF output (`SARIF=1`) for GitHub code scanning / IDE ingestion.
- Version pinning for the Python tools: `SEMGREP_VER`, `CHECKOV_VER`, `PIP_AUDIT_VER`.
- Immutable digest pinning for the docker tools: `GITLEAKS_DIGEST`, `TRIVY_DIGEST`, `SYFT_DIGEST`.
- CI: shellcheck on all scripts + a dogfood job that runs the kit's own secret scan.

### Changed
- **pre-commit** now runs a staged-secret scan on *every* commit (previously secrets were
  only caught at push time), and runs `scan.sh deps` only when a dependency manifest changes.
- `fast` scope is now `staged + deps` (was full-history `secret + deps`).
- README restructured: bootstrap-from-repo is the primary install; the lateral `cp` method
  is now explicitly labeled "offline copy from another local project", plus a clone variant.

### Fixed
- The pinning claim is now true end-to-end: semgrep/checkov/pip-audit were previously run
  unpinned via `uvx`. The new `pyrun` helper pins them and also fixes the pipx fallback
  (`--from` vs `--spec`).

## [1.0.0] - 2026-06-16

### Added
- Initial public release: portable, CI-independent local security scanning across secrets
  (gitleaks), SAST (semgrep), dependency CVE (pip-audit + js audit), IaC (checkov),
  container/fs (trivy), and SBOM (syft).
- Git-hook triggers (pre-commit / pre-push) and `bootstrap.sh` pinned-vendor installer.
- Two Claude skills: `sec-triage` (finding triage) and `sec-sast-deep` (semantic SAST).

[1.2.0]: https://github.com/boraeresici/security-audit-kit/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/boraeresici/security-audit-kit/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/boraeresici/security-audit-kit/releases/tag/v1.0.0
