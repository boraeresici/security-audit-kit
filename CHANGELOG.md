# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.12.0] - 2026-07-10

### Changed (Phase A — sharper judgment: `sec-triage` + `sec-sast-deep`)
- **Hard-evidence bar for a REAL verdict.** Both skills now default to **FP** and require, to call a
  finding REAL, that you name all three: the **sink** (`file:line`), the **untrusted source** (a
  specific attacker-controlled input — not a constant/enum/framework-metadata/trusted-process
  output), and an **unbroken path** with no effective mitigation. A pattern match is not evidence of
  exploitability. An enumerated mitigation that actually covers the path (parameterization, argv +
  no `shell=True`, escaping / safe API / sanitizer, allow-list / constant, path-root or scheme/host
  validation, an authz decorator or ownership filter, a non-privileged trigger context) forces FP —
  credited only when genuinely present, never invented, never ignored. Folds in the
  claude-code-security-review FP-filtering patterns (C1). Credit seclab-taskflow-agent + claude-code-security-review.
- **Consistency-validation pass** before writing the findings file: re-read the REAL/UNCERTAIN list
  adversarially — every REAL must carry a concrete sink + named source; no double standard (same
  sink+mitigation ⇒ same verdict); severity ranks, never decides. Failing findings are corrected
  before the file is written.
- **Context-slice hygiene + codified funnel** in `sec-triage`: read `summary.json` / the raw log
  *through tools* per finding (never paste whole dumps); only `scan.sh` survivors enter triage.
- The daily findings table now records the **untrusted source** alongside the sink, so each REAL
  carries its evidence chain on the page.
- **`sec-audit` gains an opt-in whole-repo blueprint** — a 3-stage deep mode (threat-model the repo
  → per-component name the vuln classes worth auditing → audit each at the hard-evidence bar, with a
  cross-set consistency sweep), distinct from the routine scan+triage default. Most token-costly
  path; announced, scoped, and targeted (not file-by-file, not exhaustive — carries a "not audited +
  why" note). Credit seclab-taskflow-agent's threat-model→plan→audit shape.

### Added (measured before/after — the Phase-A acceptance gate)
- Re-measured the judgment prompt (`tests/eval/triage_prompt.md`, the eval mirror of the skills)
  on GLM-5.2 via NIM. **Held-out FP rate 3 → 0 with recall held at 100%** (precision 83.3% → 100%);
  dev split held at 31/31 (no recall regression). Three fixed cases were seen during earlier
  debugging (confirmatory), so **six fresh held-out twins in classes the prompt never names (LDAP /
  CRLF / XPath) were added after freezing the prompt** as a blind generalization check — GLM scored
  6/6. Full held-out now 36 cases at precision/recall 100%. Documented in `docs/compare/aikido-semgrep.md`.

## [1.11.2] - 2026-07-10

### Changed (eval harness — corpus expansion + measurement hardening; still dev-only, not in the scan path)
- **Corpus grown 10 → 61 cases, split dev / held-out.** `cases.yaml` is now a **31-case dev (tuning)
  split** and `cases.holdout.yaml` a **30-case held-out split** that produces the reportable number
  and must not be read while tuning the prompt. Coverage spans **21 vuln classes** (sqli, command/
  code injection, path traversal, SSRF, deserialization, SSTI, XSS, XXE, weak-crypto, broken-auth,
  mass-assignment, IaC misconfig, CI injection, prompt-injection / insecure-output-handling,
  dependency-CVE, NoSQL, open-redirect, …) and **11 FP classes**. Most REAL cases have an FP **twin**
  (same class, one decisive difference: sanitizer / allow-list / reachability / safe API variant),
  tagged `difficulty: hard` — this is what gives the corpus resolving power the old 10-case set lacked.
- **Split enforced mechanically.** Every config loads both files; `run.sh` selects one via
  `--filter-metadata split=<dev|holdout>` (new `EVAL_SPLIT`, default `dev`; held-out writes
  `output.holdout.json`).
- **`score.mjs` no longer charges provider errors to the model.** A case that never reached the model
  (auth/billing/network — promptfoo `failureReason=2`) is excluded; an all-errored run now **refuses
  to report and exits 2** instead of printing a plausible-looking `0%`. New `EVAL_ALLOW_PARTIAL=1`
  scores only the cases that ran. Exit codes: 0 ok / 1 regression gate unmet / 2 no usable data.
- **Shared grader.** All configs point at one `grade.mjs` (`file://`) so a scoring change can never
  land on some backends and not others (keeps cross-backend scores comparable). New `EVAL_CONCURRENCY`
  knob (default 4) to dodge free-tier rate limits.
- **New backend variants** (OpenAI-compatible, key-gated, same corpus/prompt/grader): GLM-5.2 via
  NVIDIA NIM (`promptfooconfig.nim.yaml`), GLM-5.2 via Z.ai (`.glm.yaml`), Mistral Large 3 (`.mistral.yaml`).

### Added
- **First held-out measurement** (GLM-5.2 via NIM, 2026-07-10): dev split 31/31; **held-out split
  precision 83.3%, recall 100%, F1 90.9%, accuracy 90%** (TP=15, FP=3, FN=0, TN=12). All three misses
  are `difficulty: hard` FP twins the model over-flagged — the harness can now *see* a precision failure,
  the precondition for measuring Phase-A prompt changes. Documented in `docs/compare/aikido-semgrep.md`
  ("Measured triage quality"). The default backend (Claude) stays unmeasured pending API credit.

### Fixed
- **Nunjucks templating collision in fixtures.** promptfoo renders case code through Nunjucks, so a
  JSX `dangerouslySetInnerHTML={{ __html: … }}` brace-pair with a colon was a template syntax error.
  Fixtures now avoid literal `{{ }}` except valid GitHub Actions `${{ … }}` expressions.

## [1.11.1] - 2026-07-03

### Added (eval harness — dev-only skill-quality regression; not in the scan path)
- **`tests/eval/`** — a promptfoo-based (`@0.121.17`, pinned) harness that grades the `sec-triage`
  **REAL/FP judgment** against a labeled corpus (`cases.yaml`: 5 real exploitable findings + 5
  false positives across the classes triage must suppress — test-only, not-reachable, dev-placeholder,
  safe-parameterized, allow-listed). `run.sh` feeds each case + a provider-neutral distillation of the
  skill's Pass 1/2 (`triage_prompt.md`) to a model and `score.mjs` reports precision / recall / F1 /
  accuracy for the REAL class. This is roadmap **Tier-L L1** — the gate for Phase-A prompt changes and
  any future local / other-provider backend (change `providers:` to grade a candidate on the SAME
  corpus). Optional regression gates: `EVAL_MIN_RECALL` / `EVAL_MIN_PRECISION`. **Dev-only:** needs
  `node`/`npx` + a provider key (`ANTHROPIC_API_KEY`); skips cleanly (exit 0) otherwise, so it never
  hard-fails CI/e2e. CI `shellcheck` now also lints `tests/eval/run.sh`; e2e smoke-tests the skip path
  + `score.mjs` math; `output.json`/`.promptfoo/` gitignored.

## [1.11.0] - 2026-07-03

### Added (two new optional scan dimensions — supply-chain + CI/CD coverage)
- **`scan.sh guarddog`** — malicious/typosquat **dependency** detection via **GuardDog**
  (`==3.0.2`, Apache-2.0), run through uvx/pipx. `guarddog verify` checks each declared dependency
  (`requirements*.txt` → PyPI, `package.json` → npm) against the live registry for typosquatting,
  compromised-maintainer metadata, and malicious install scripts — the blind spot of the CVE
  scanners (osv/pip-audit/npm only find *known* CVEs). **HARD when run; standalone (not in `all`);
  needs network.** `GUARDDOG_VER` pin; `doctor` + conf + READMEs + e2e updated.
- **`scan.sh zizmor`** — GitHub Actions security via **zizmor** (`==1.26.1`, MIT), run through
  uvx/pipx, **offline** (no GitHub API → deterministic/air-gap friendly). Flags template injection,
  dangerous triggers (`pull_request_target`), token over-permissioning, credential persistence,
  unpinned actions. Runs only when `.github/workflows/` is present. **HARD when run; standalone
  (not in `all`).** SARIF supported (`SARIF=1`). `ZIZMOR_VER` pin + `ZIZMOR_ARGS` passthrough
  (e.g. `--min-severity medium`); `doctor` + conf + READMEs + e2e updated.

### Changed (self-dogfooding — the kit now passes its own zizmor gate)
- Hardened the kit's **own GitHub Actions workflows** to pass `scan.sh zizmor`: least-privilege
  `permissions:` blocks (top-level `contents: read` + job-scoped `security-events: write` only where
  SARIF upload needs it) and `persist-credentials: false` on all `actions/checkout` steps.

## [1.10.1] - 2026-07-03

### Added (maintainer tooling — no change to scan behavior or skills)
- **`RELEASING.md` + `scripts/release.sh`** — RC-gated release flow. Consumers pin to release tags,
  so every stable `vX.Y.Z` is gated behind a dogfooded `vX.Y.Z-rc.N` **pre-release**, and the final
  tag is cut on the **exact tested RC commit**. `release.sh` runs a preflight (on `main`, clean tree,
  in sync with origin, `scan.sh verify`, `e2e`, required CI checks green via `gh`) then cuts
  `rc` / `final` tags + GitHub releases (`preflight` / `rc [X.Y.Z]` / `final X.Y.Z`; `--yes`/`--skip-e2e`/`--no-gh`).
- **e2e stack fixture matrix** — `tests/fixtures/stacks/{django,react,terraform,monorepo}` (benign
  `.tpl` fixtures, materialized per-stack into throwaway repos) assert stack-aware detection in
  isolation; catches "wrong packs in a real project" before merge. 5 new assertions (36/0 total).
- **`.github/rulesets/main.json`** — importable branch-protection ruleset for `main` (PR required;
  required checks `shellcheck`/`checksums`/`self-audit`; no force-push/delete) + a README with UI/`gh`/manual apply steps.

### Changed
- CI `shellcheck` job now also lints `scripts/release.sh`.

## [1.10.0] - 2026-06-25

### Added (stack-aware injection coverage)
- **`scan.sh` now auto-selects semgrep packs from the repo's stack.** With `SEMGREP_CONFIGS`
  unset, it builds the ruleset from what's actually present: base `p/owasp-top-ten` + `p/secrets`,
  plus the detected language/framework packs — `p/python`/`p/django`/`p/flask`,
  `p/javascript`/`p/typescript`/`p/react`, `p/golang`, `p/java`, `p/php`, `p/ruby`, `p/csharp`.
  So a Django project gets Django's ORM-injection rules, a React project gets its XSS rules, etc.,
  instead of a one-size config. Only registry packs verified to exist are referenced (a missing
  pack would hard-fail this deterministic gate). Detection is git-based + manifest-content for
  frameworks; `node_modules` excluded. **Override unchanged:** set `SEMGREP_CONFIGS` (env/conf) and
  it wins verbatim — nothing is appended. `scan.sh doctor` now prints the resolved set and whether
  it is `stack-auto` or `from env/conf`; the `sast` log line shows the packs used.
- **`sec-sast-deep` gains Class 4 — semantic/stack-specific injection** (semgrep's blind spot):
  second-order/stored injection, wrapper-hidden sinks, and stack idioms the pattern packs miss
  (Django/SQLAlchemy `.raw()`/`.extra()`/`text()`, Flask `render_template_string` SSTI, Node
  `child_process`/`eval`/NoSQL operator injection, Java `Statement`/OGNL, unsafe deserialization).
  It reads the stack `scan.sh` detected and explicitly defers single-sink findings to `scan.sh sast`
  (no double-reporting). `sec-audit` now also triggers `sec-sast-deep` on raw-injection-sink signals.

### Changed
- `security-audit.conf.example`: `SEMGREP_CONFIGS` is now commented out by default (leave unset =
  stack-auto); documented that setting it overrides auto-selection verbatim. READMEs (en/tr) updated.

## [1.9.2] - 2026-06-25

### Fixed (secret scan in a git worktree — silent false-clean)
- **gitleaks now works in a git worktree.** A worktree's `.git` is a *file* pointing to a gitdir
  outside the worktree, so gitleaks-in-docker (mounting only the worktree) couldn't reach the
  history and silently reported "no leaks" (exit 0) — a dangerous false-clean. `scan.sh` now also
  mounts the common gitdir (`git rev-parse --git-common-dir`) when `.git` is a file. **No-op for a
  normal repo** (`.git` is a directory). Covers `secret` + `staged`. New e2e: a committed secret
  is caught when scanned from a worktree. (Found via a dogfooding question.)

> Note: normal branches were never affected — `scan.sh` scans the current checkout / branch (not
> `main`); semgrep/trivy/checkov already worked in worktrees too.

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

[1.9.2]: https://github.com/boraeresici/security-audit-kit/compare/v1.9.1...v1.9.2
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
