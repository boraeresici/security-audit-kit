# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.9.1] - 2026-06-24

### Fixed (dependency-scan reliability — found via dogfooding)
- **pip-audit now audits the project's environment, not uvx's empty one.** It points
  `PIPAPI_PYTHON_LOCATION` at an active `$VIRTUAL_ENV` (else the repo's `.venv`); without one it
  says so and suggests `scan.sh osv`. Previously "No known vulnerabilities found" was effectively
  auditing nothing for venv/uv projects.
- **JS audit now includes dev/build dependencies** (dropped `--prod` / `--omit=dev`). Vulns in
  build tooling (vite, undici, …) are real and were silently skipped; the triage layer decides
  reachability. **Note:** this may surface previously-missed dev-dep vulns and block a pre-push —
  that's the fix working; allowlist/triage as needed.
- **trivy skips build-output dirs** (`TRIVY_SKIP_DIRS`, default `**/.next,**/dist,**/build,…`) —
  removes the noise/memory/slowness from scanning `.next` etc. (which also contributed to a
  concurrent-run log garble). Configurable in `.security-audit.conf`.

> For lockfile-accurate, all-ecosystem dependency CVEs (incl. transitive + dev), `scan.sh osv`
> remains the most reliable — it reads `uv.lock`/`pnpm-lock` directly.

## [1.9.0] - 2026-06-24

### Added
- **`sec-audit` orchestrator skill** — a one-command entry point: runs `scan.sh all` + triage,
  then runs **only the deep passes the repo calls for** (signal-gated: `sec-sast-deep` on authz
  surfaces, `sec-ai-review` if the code calls an LLM, `sec-threat-model` for a new subsystem; all
  on `deep`), and consolidates into one `findings-<DATE>.md`. Cost-aware + transparent: announces
  which deep pass runs and why before spending tokens; default = scan + triage only (respects the
  cadence). Installed into `.claude/skills/`; READMEs + e2e updated.

## [1.8.0] - 2026-06-24

### Added
- **`scan.sh osv`** — optional broad multi-ecosystem dependency-CVE dimension via **OSV-Scanner**
  (Google), pinned by docker digest (`v2.4.0`). Scans lockfiles across py/js/go/rust/… against
  OSV.dev; HARD when run (exit 1 = vulnerabilities). Standalone / opt-in (NOT in `all`) so it does
  not double-gate with pip-audit/npm/trivy. SARIF supported (`SARIF=1`). `OSV_VER`/`OSV_DIGEST`
  pins; `doctor` + conf example + e2e + READMEs updated.

## [1.7.0] - 2026-06-23

### Added (adoption / interop)
- **`.pre-commit-hooks.yaml`** — use the kit via the [pre-commit](https://pre-commit.com)
  framework: `sec-staged` (every commit), `sec-deps` (on a manifest change), `sec-all`
  (pre-push / manual). An alternative to the kit's own git hooks.
- **`install.sh --skills-only`** — installs the skills + config WITHOUT setting
  `core.hooksPath`, so pre-commit-framework users get the Claude skills without a hooks clash.
- e2e covers both (`.pre-commit-hooks.yaml` validity + `--skills-only` leaves hooksPath unset).

## [1.6.0] - 2026-06-23

### Added (supply-chain hardening — Tier S Layer 0)
- **`bootstrap.sh --expect=<sha>`** (or `KIT_EXPECT_SHA`) — *enforces* the pin: refuses to vendor
  if the ref resolves to a different commit than you reviewed (defends against a wrong ref).
- **Tag-repoint guard** — re-vendoring an already-pinned ref that now resolves to a *different*
  commit is refused (the tag/branch moved) unless you pass `--allow-ref-change`. Turns the pin
  from a recorded value into an enforced one. e2e covers both (refuse + accept) offline.

## [1.5.0] - 2026-06-23

### Changed (skill content enrichment — no new infra)
- **`sec-triage`:** before deferring/allowlisting a *dependency CVE*, check **CISA KEV** +
  **EPSS** on demand (just those CVEs) — in KEV / high EPSS → do not defer. Lightweight close of
  the KEV/EPSS idea (no vendored feeds; the kit stays offline, the lookup stays fresh).
- **`sec-sast-deep`:** added a "past-fix recurrence & incomplete patches" bonus pass — diff recent
  security commits for incomplete fixes; grep the codebase for siblings of a past finding's pattern.
- **`sec-ai-review`:** added an explicit untrusted-text-surfaces checklist (8 surfaces, from Lyrie's
  "Shield Doctrine") + named attack classes (crescendo / tap / pair / gcg / autodan) for static review.

## [1.4.0] - 2026-06-23

### Added
- **`sec-threat-model` skill** — STRIDE + data-flow threat modeling of the repo's attack surface
  and trust boundaries (higher-altitude than `sec-sast-deep`). Judgment-only; installed into
  `.claude/skills/`; writes a living `docs/security/threat-model-<DATE>.md` and promotes concrete
  gaps into the `sec-triage` flow. READMEs (intro, lifecycle diagram, cadence table) + e2e updated.

## [1.3.1] - 2026-06-17

### Changed (supply-chain hardening of the kit's own CI/test tooling)
- Pin the CI shellcheck image by **immutable digest** (was the `:v0.10.0` tag).
- Pin all **GitHub Actions by commit SHA** (`actions/checkout`, `astral-sh/setup-uv`,
  `github/codeql-action/upload-sarif`) with a `# vX.Y.Z` comment — mutable tags can be repointed.
- Fix the `install.sh` summary wording: pre-commit runs a staged-secret scan on every commit
  (+ `deps` on a manifest change), not `fast`; add `changed` to the listed scopes.

> Note: the kit's docker scan tools (gitleaks/trivy/syft) were already digest-pinned. The
> Python tools (semgrep/checkov/pip-audit) remain **version-pinned, not hash-pinned** — tracked
> as a roadmap item to discuss before implementing.

## [1.3.0] - 2026-06-17

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

[1.9.1]: https://github.com/boraeresici/security-audit-kit/compare/v1.9.0...v1.9.1
[1.9.0]: https://github.com/boraeresici/security-audit-kit/compare/v1.8.0...v1.9.0
[1.8.0]: https://github.com/boraeresici/security-audit-kit/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/boraeresici/security-audit-kit/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/boraeresici/security-audit-kit/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/boraeresici/security-audit-kit/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/boraeresici/security-audit-kit/compare/v1.3.1...v1.4.0
[1.3.1]: https://github.com/boraeresici/security-audit-kit/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/boraeresici/security-audit-kit/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/boraeresici/security-audit-kit/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/boraeresici/security-audit-kit/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/boraeresici/security-audit-kit/releases/tag/v1.0.0
