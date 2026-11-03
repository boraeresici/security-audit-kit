# Security Audit Kit — evaluation backlog

Source: [2026-09-08 multi-role evaluation](application-review-2026-09-08.md). Local base: `48fad91`.

**Update — 2026-09-10:** Following the 2026-09-08 evaluation, 3 new F cards (F23–F25) and 1 conditional R card (R11) were added. F22 is done; the remaining 24 F cards and 11 R cards are below. F23–F25 close gaps in existing cards: Python module tests (a prerequisite of F09), config validation (an application extension of F11) and a consumer upgrade guide (a complement to F08). R11 is tool pin update automation and is left conditional. An F12 measurement note was added: the calibration scorer implementation, first Qwen 3.7 Max + GLM-5.1 measurement results and the decision record. [Roadmap mapping and decision rationale](roadmap-reconciliation-2026-09-08.md).

**Update — 2026-09-14:** The SkillSpector and UI evaluation was worked into the plan: **F26** serverless HTML report usability (P2), **R12** optional SkillSpector pilot (P2 candidate), **R13** local UI that starts scans (conditional). The new items' own order is F26 → R12 → R13 if needed; existing P0/P1 reliability work comes first. The CLI is kept as the shared execution layer. The earlier card counts are the 2026-09-10 record; this update adds one F and two R cards.

**RC status check — 2026-09-14:** F23's 234 unit tests and 93 offline e2e assertions passed. RC.1's invalid `actions/setup-python` pins were fixed to v6 in RC.2; the remote ruleset was mapped to five checks including pytest/e2e and post-merge CI ran green. F09 and F23 are done. In the RC.2 real-consumer dogfood, the old bootstrap's two-field pin fallback was correctly rejected because CHANGELOG was still `Unreleased`. RC.3 prepares the CHANGELOG version and adds a pre-tag version-match gate to the release script.

**Update — 2026-10-11:** The Cloudflare comparison (local note `docs/compare/cloudflare-security-audit-skill.local.md`) was mapped against local code at `078cf18`. **F27** recorded deep-review coverage and **F28** independent validation pilot were added; **R14** domain playbooks is a conditional reserve. F11/F12/F19 acceptance criteria were extended. The P0/P1 order is kept; F19 → F27 → F28 is the new AI review track. F26/R12 stay where they were. These are plan changes; the features are not implemented yet.

**Update — 2026-10-21:** While implementing F01, the py-deps failures in local e2e were investigated. The cause was `VIRTUAL_ENV` set in the developer shell; the tests were made hermetic. The same investigation also revealed a product bug: when the repo has no `.venv`, an active environment that does not belong to the project is audited. Added as **F29** (P1, slot 3a). This is a plan change; the fix is not implemented yet.

**Order change — 2026-11-02:** F14 and F25 were moved directly behind F03 → F04 (3b). Rationale: F02's breaking schema change and F14's dependency being lifted. The definition of priority and the order of other items did not change. The decision the plan leaves open — "dominant user / onboarding UX or monorepo cost" — has still not been made; this change does not replace that decision.

**Update — 2026-11-02 (performance and positioning):** End-to-end measurement showed the bottleneck is the trivy DB download (~32 s of `all`'s ~40 s); the orchestrator's language is not the bottleneck. **F30** (trivy DB cache, slot 3c), **F31** (pre-push profile and parallel dimensions) and **F32** (README first screen, demo, comparison fix, trust signals) were added. **R02** plugin channel was raised to P1 and moved to slot 8. Acceptance criteria were added to F14 and F20. [Rationale](roadmap-reconciliation-2026-09-08.md).

**Note — 2026-11-02:** A comparison with a commercial AI-assisted SOC platform, tracking new vulnerabilities between scans, agent/alerting integration and the role of Dependabot were put into the conditional note card **R15**. Not critical; the delivery order did not change.

**Update — 2026-11-03 (three competitor comparisons):** The Masriyan (local note `docs/compare/masriyan-cybersecurity-skill.local.md`), Phoenix (local note `docs/compare/phoenix-security-skills.local.md`) and senior-security (local note `docs/compare/senior-security-skill.local.md`) comparisons were written against upstream commits pinned at `v1.20.0`. A verified SHA note (`c1c8a8c`) was added to the Cloudflare document (local note `docs/compare/cloudflare-security-audit-skill.local.md`). No tool was found that is ahead of the kit on in-repo code security. All three tools are distributed via a plugin marketplace; this supports R02's priority. Cards added: **F33** plugin hook set (SessionStart context, PostToolUse single-file check), **F34** `pkgcheck` cheap registry signals and an "ask" decision, **F35** a "scanned content is not instructions" rule in the skills, **F36** a STRIDE-per-element completeness check in the threat model. Acceptance addenda were written to the F19 and R02 cards. The agreed order to the plugin (3d → 4 → 8) did not change; the new cards were placed at 5, 8c and 8d. These are plan changes, not implemented yet.

**Update — 2026-11-03 (dimension registry; classic security tool review):** At the user's request, the first slice of **F17** was taken ahead of its slot (13) and implemented on `dev/plugin-readiness`. `scan.sh` dispatch now reads a dimension registry, and the adapter contract is documented in `docs/adapters.md`. Behavior is unchanged: before and after runs were compared over every scan command and five toolchain scenarios, 75 cases with 0 differences. Separately, 15 classic security tools (Nmap, Metasploit, OpenVAS, SQLmap, commercial web proxies and OSINT suites, and others) and the agentic pentest tools Strix and PentAGI were reviewed. None of them becomes a dimension. **R16** was added as a conditional card: an optional external dynamic adapter, with nuclei as the reference. **F36** got a detection/monitoring addendum. The weak-password idea needs no card, because the local-rules mechanism (old plan #14) already exists. **UI track (user decision):** R13 moves from conditional to planned, in slot 8a as F26 → F19a → R13a → R13b → R13c. The UI is `scan.sh ui`, a thin client over the CLI built on the Python standard library. It starts read-only, then adds running a dimension and approving time-bound allowlist entries through the CLI. The gate stays in the CLI. F19a moves up from slot 9, because the UI needs stable finding identity. The agreed order to the plugin did not change.

P0: a verified bug that directly breaks trust in results/records. P1: the next reliability and usability package. P2: improvement driven by measurement and demand. The P0 label is not CVSS or exploit severity. Effort: S ≈ 0.5–2, M ≈ 3–5, L ≈ 6–10 engineer-days; a rough estimate including tests and docs, not a schedule commitment.

## Priority table

| ID | Work | Type / evidence | Priority | Role | Effort | Dependency |
|---|---|---|---|---|---|---|
| F01 | Isolate all outputs of a run that cannot take the lock | Bug / V | P0 | Backend | M | — |
| F02 | Separate scan result from blocking policy | Bug / V+C | P0 | Backend + security | M | — |
| F03 | Bind evidence/SARIF to the run identity | Bug / V | P0 | Data + backend | M | F01 |
| F04 | Report contract that does not show missing/broken evidence as clean | Bug / V+C | P0 | Reporting + UX | S | F02, F03 |
| F05 | Fix lock ownership and long-run races | Risk / C | P1 | Backend | M | F01 |
| F06 | Refresh package cache decisions on policy change | Risk / C | P1 | Security | M | — |
| F07 | Stop on unverifiable CI in stable release | Risk / C | P1 | Release | S | — |
| F08 | Separate stable/RC update channels | Risk / C | P1 | Release | S | — |
| F09 | Make deterministic e2e a PR gate | Quality / C | Done | QA + CI | M | 5 required checks active remotely |
| F10 | Install and rollback that preserve existing hooks | UX / C | P1 | DX | M | — |
| F11 | Map the kit's own trust boundaries and hardening options | Risk / C | P1 | Security | M | — |
| F12 | Calibration preparation → measurement → decision contract | Research / C | P1 | AI + security | L | a: none; b: accessible backend; c: measurement |
| F13 | Fix local/offline/data-sharing statements | Docs / C | P1 | Product + security | S | — |
| F14 | a: coverage/closing summary, help, quick start; b: quiet output and first finding line | UX / P | P1 | Product + DX | a: M; b: M | a: F02; b: F31b |
| F15 | Landing resilience and accessibility check | UX / C+P | P2 | Frontend + QA | S | — |
| F16 | Add missing dimensions to the normalized evidence model | Enhancement / C | P1 | Data | L | F02, F03 |
| F17 | Split shell orchestration into modules incrementally | Maintenance / P | P2 (slice 1 done) | Architecture | L | F09, behavior contracts |
| F18 | Platform and paths-with-spaces test matrix | Quality / C+P | P1 | QA + DX | M | F09 |
| F19 | Finding identity and shared decision record | Enhancement / C+P | P2 | Data + security | L | F03, F16 |
| F20 | Local performance and coverage metrics | Enhancement / P | P2 | Operations + product | M | F02, F03 |
| F21 | a: dimension cache; b: monorepo scope | Enhancement / P | P2 | Performance | L | a: F03, F05, F06, F20; b: a + need |
| F22 | Tie roadmaps to a single current backlog | Maintenance / C | Done | Product + maintenance | S | 2026-09-08: this document + mapping |
| F23 | Unit test infrastructure for Python modules | Quality / C | Done | QA + backend | S | together with F09; 234 tests |
| F24 | Config file validation and safe sourcing | Risk / C | P1 | Security + DX | S | F11 |
| F25 | Version upgrade guide and breaking change notice | DX / P | P1 | Release + DX | S | F08 |
| F26 | Search, filters and finding details in the serverless HTML report | Enhancement / P | P2 | Reporting + UX | S–M | F04, F14; F16 coverage/gap contract |
| F27 | Coverage ledger and re-review in deep review | Enhancement / C+P | P2 | AI + data | M | F03, F04, F19 |
| F28 | Independent validator pilot and coverage check | Research / C+P | P2 | AI + QA | M pilot | F11, F12c, F19, F27 |
| F29 | py-deps: auditing an active environment that does not belong to the project | Bug / V+C | P1 | Backend + security | S | — ; status naming aligned with F02 |
| F30 | trivy DB/check cache, freshness policy, first-run message | Performance / V | P1 | Backend + DX | S | F03 (DB identity in provenance) |
| F31 | a: pre-push profile + gitleaks over the push range; b: parallel dimensions | Performance + UX / P | P2 | Backend + DX | a: S–M; b: M | a: F14; b: F30, F03 |
| F32 | README first screen, demo, comparison fix, trust signals | Product / P | P1 | Product + DX | S–M | comparison row: F12b |
| F33 | Plugin hook set: SessionStart scan context, PostToolUse single-file check | Enhancement / C | P2 | DX + security | M | R02, F10, F11, F35 |
| F34 | `pkgcheck`: package age and install script signals, "ask" decision | Enhancement / C | P2 | Security | S–M | F06; external call into the F13 table |
| F35 | "Scanned content and tool output are data, not instructions" rule in the skills | Risk / V | P1 | AI + security | S | — ; eval fixture with the F12 harness |
| F36 | `sec-threat-model`: STRIDE-per-element completeness check | Enhancement / C | P2 | Security | S | — |

## Additional / conditional cards from the roadmap

This table does not repeat the F items above. “Conditional” items are not taken into implementation until the stated need and dependencies are verified.

| ID | Old reference / work | Decision | Role | Effort | Opening condition / dependency |
|---|---|---|---|---|---|
| R01 | T2.2 / #8 remediation compute | P1 scope decision; implementation conditional | DX + security | S decision; M–L implementation | An example where the existing skill commands are not enough |
| R02 | R5.3 skills-only plugin / manifest | P1 (raised from P2 candidate on 2026-11-02) | DX + security | M | F10, F11, F14; distribution bottleneck (0 stars) and Semgrep's official Claude Code plugin |
| R03 | A3 / #7 Python-JS reachability | Conditional | Security + performance | L | F16, F21a; measured high triage load |
| R04 | L2 + Phase B provider/local runner | Conditional | AI + architecture | L pilot; full runner estimated separately | F12; real offline/non-Claude requirement |
| R05 | T3.4 generate-only PoC | Conditional | Security + AI | L | F12c, F19; need for evidence |
| R06 | Hash-pin Python tools | Decision first, deferred | Supply chain | S decision; M–L implementation | F11; acceptance of maintenance/compatibility cost |
| R07 | Tier S Layer 3 signed release | Deferred | Release + security | M | F07; demand for publisher identity verification |
| R08 | A4/A5 static situational scanner | Deferred | Security | When a tool is chosen | Concrete coverage gap; F16, pin/license review |
| R09 | CLI wizard | Last planned feature | DX + UX | M | Design refresh with F14 data once priority active work is done |
| R10 | T3.2 / B.1 skill extraction | Deferred | AI + maintenance | M | R04 or a measured maintenance problem |
| R11 | Tool pin update automation | Conditional | Supply chain + maintenance | M | R06, F07; when 3+ tool versions go stale or a CVE is reported |
| R12 | SkillSpector: skill security scanning dimension | P2 pilot candidate | Security + data | S pilot; M integration | F11/F13; integration F02/F03/F16; default order after F26 |
| R13 | Local UI that starts scans on top of the CLI | Planned P2 (2026-11-03; was conditional): R13a read-only → R13b run → R13c allowlist approval | Backend + UX | M–L | F26, F19a; F01–F05, F11/F24 |
| R14 | Signal-selected expert review playbooks | Conditional P2 | Security + AI | S selection; M / domain | F12 eval coverage, F27; coverage gap at a real consumer |
| R15 | New vulnerability tracking, event output and agent access | Note / conditional | Security + integration | a: S; b: S–M; c: M–L; d: M | a: none; b: F01; c: F03, F19; d: c, F11, F13; real consumer demand |
| R16 | Optional external dynamic adapter (nuclei reference) | Conditional | Security + integration | M | F17 registry (done), F16b normalizer; real consumer request for a live-target check |

## Work cards / acceptance criteria

### F01 — Run isolation

A scan whose lock wait times out must not modify another scan's summary/SARIF/evidence/HTML files. Each run must get a unique directory and identity; updating the last-completed-run pointer must follow an explicit ownership rule. A test with two concurrent scans and a lock timeout must verify that all artifacts stay with their own run. A cancelled run must not corrupt the last successful record.

**Status:** done, released in v1.19.0 (PR #32). Moving old SARIF was left to F03.

### F02 — Status and policy

A dimension result must carry at least the distinction `pass`, `findings`, `error`, `skipped`, `indeterminate`, `not_applicable` and its reason; naming may be finalized in the schema design. The `gate` result must be computed separately. There must be fixtures for missing Docker/uvx, a missing manifest, a tool crash and a soft-fail finding. The schema migration must be documented for existing consumers. The false `pass` must be fixable without changing the default fail-open decision.

**Decision — 2026-11-02:**
- **Naming:** the six names on the card were used as-is. The values of the `status` field were changed in place and `schema_version: 2` was added. The old `fail` value was removed. Keeping the old field and adding a new field next to it was also considered, but then the old field would keep writing a false `pass` for skipped dimensions.
- **Gate:** behavior unchanged; the gate is still computed from the return code. The status comes from the function's explicit mark (`dim_mark`/`dim_skip`/`dim_na`/`dim_error`) or from the default mapping. Whether scan errors should block was left open as a separate policy question.
- **Indistinguishable states:** pip-audit, gitleaks, npm/pnpm/yarn audit and guarddog use the same exit code for a finding and an error. These are recorded as `findings`; this limitation is written in the contract.
- **Contract:** [docs/schema/summary.md](../schema/summary.md).

**Status:** implemented on branch `feat/f02-status-policy`. 18 checks were added to e2e; they run offline and deterministically because the tools are shimmed. There is a unit test for the status labels in the report.

### F03 — Artifact provenance and freshness

Evidence must consume only outputs in the same run manifest. Previous SARIF + a dimension skipped/failed in this run must not be taken as a current finding. Fields must be defined for commit, dirty state, scope, tool/config/rule identity and generation time. Deterministic finding generation from the same content must be preserved; run metadata must be kept separate. Missing/broken output must produce a visible warning or error.

**Decision — 2026-11-02:**
- **Run manifest:** no separate file was created; the `artifacts` field in `summary.json` (this run's SARIF files and their sha256s) does this job.
- **What evidence uses:** only files in the list whose hash matches, and only if the dimension's status is `pass` or `findings`. A warning is written for every excluded file and the builder prints these warnings.
- **Shared `sarif/`:** files from previous runs are no longer carried over; the directory is rewritten on every `SARIF=1` publish. If carrying over continued, someone uploading or reading the file could mistake an old file for a current result.
- **Provenance:** computed in `summary.json` at the start of the run. Fields it covers: commit, dirty state, kit version and CHECKSUMS hash, config hash, rules, tool pins, scope. It contains no time or run id; it is copied as-is into evidence.json and the same content keeps producing the same output.
- **`SARIF=0` runs:** runs such as pre-commit do not touch the `sarif/` directory or evidence.json. Which commit they describe is written in provenance.

**Status:** implemented on branch `feat/f03-artifact-provenance`. 7 checks were added to e2e and 9 to the unit tests.

### F04 — Honest report

If there is no exit code or coverage is incomplete, the HTML must not say `clean`. A tool error must not be presented as a finding; a zero gate code must not mean “all dimensions clean”. Scan date and report generation date must be separated. If an explicitly invoked `report`/`evidence` could not be produced, a machine-readable failure must be returned; the effect on the gate of a report error after an optional scan must be documented separately. The null/missing/3/1/0 states must be tested.

**Decision — 2026-11-02:**
- **Verdict line:** the report header shows a single verdict: `clean`, `passed — findings present but not blocking`, `passed — NOT complete`, `blocked` (with the name of each blocker; a crashed tool as "scan error, not a finding"), `indeterminate` or `unknown`. `clean` is written only if two conditions hold together: every applied dimension inspected something and no findings are reported.
- **Scan time:** taken from `summary.json`, but only if the summary belongs to the evidence's own run. To determine this, `dimensions`, `artifacts` and `provenance` are compared; this is why `scan.artifacts` was added to evidence. No time was written into evidence, so the same content still yields the same evidence. The report date is shown separately next to it.
- **Explicit commands:** `scan.sh evidence` / `scan.sh report` exit with 1 if they cannot produce their files.
- **Post-scan error:** an error that occurs at the end of a scan with `SARIF=1` / `REPORT=html` is printed to the screen but does not change the gate. Rationale: the gate is the scanners' decision; a report that cannot be rendered does not change what they found.

**Status:** implemented on branch `fix/f04-honest-report`.
- 15 unit tests were added: null/missing/3/1/0 for `verdict`, `scan_time` and the header.
- 6 e2e checks were added. When run against the old code on `main`, all 6 came out red.

### F05 — Lock lifecycle

The lock of a live, long-running scan must not be taken solely because of its age. Release must remove only the lock carrying its own token. Dead PID, PID reuse, missing heartbeat, simultaneous stale reclaim and INT/TERM tests must be done. A corrupt lock file must not lead to an infinite wait.

**Status:** done, released in v1.19.0 (PR #34).

### F06 — Policy-aware package cache

A policy that first allows and then blocks the same package/version with `BLOCK_EXTRA` must be applied correctly. The cache key or reclassification must cover the policy/rule version. Missing/partial cache and concurrent writes must be handled atomically. The refresh rule and the `refresh` path for exact-version and versionless requests must be documented; INDETERMINATE must not turn into a persistent clean decision.

**Decision and status — 2026-11-03:** implemented on branch `dev/plugin-readiness`.
- **What is cached:** not the decision itself, but guarddog's raw findings. The network scan is the slow part; judging the findings is fast.
- **Policy change:** the current policy (`BLOCK_EXTRA` / `REPORT_EXTRA`) is reapplied on every read. So a policy change takes effect immediately without a re-download, and there is no need to put a policy version in the key.
- **Key:** a new schema with the `findings-v2` prefix; records in the old format are not read (there is an upgrade note in the CHANGELOG).
- **Write:** written to a temp file and renamed. A half-written record is ignored in the cache and the package is rescanned. INDETERMINATE is never written.
- **Refresh:** `PKGCHECK_CACHE=refresh` rescans without reading the cache and replaces the record.
- **Also fixed:** every package checked for the first time, including `BLOCK`, was shown as "ok … clean". A progress line was getting mixed into the decision line. The exit code was correct; only the message said the opposite.
- **Tests:** 10 e2e checks were added. With a fake guarddog shim, the following are tested: the result when the policy tightens and loosens, a half-written record, INDETERMINATE, refresh, the old format, concurrent writes and the `BLOCK` message on first check.

### F07 — Release gate

Missing gh, a failed API, empty/missing/pending check-runs and an unverifiable remote HEAD must stop a stable release. Selection between an old failed / new successful rerun for the same SHA must be deterministic. It must be tested with network and gh fixtures; the tests must not publish tags or releases. If an exception path is accepted, the requirement to record a rationale must be explicit in the design.

**Status — 2026-11-03:** implemented on `dev/plugin-readiness`.
- **Final is strict:** `release.sh final` and `preflight --stable` stop on any of these: no gh, a failed API call, no check-runs, a pending or missing required check, an unverifiable `origin/main`.
- **Reruns:** the newest run (highest check-run id) of each required check decides.
- **RCs:** they only warn.
- **Exception:** `--ci-unverified="<reason>"`; the reason is required and goes into the tag message.
- **Tests:** 12 offline e2e checks with a gh shim against a release repo with a bare origin; nothing is tagged.

### F08 — Update channel

In a local tag fixture containing `v1.17.0`, `v1.18.0-rc.1`, `v1.18.0`, the default suggestion must be the latest stable. An RC must be suggested only with explicit channel selection. Access error, update available and up-to-date results must be distinguished. Offline fixture tests are sufficient; no release should be opened for the test.

**Status — 2026-11-03:** implemented on `dev/plugin-readiness`.
- **Channels:** `bootstrap.sh --check` gains `--channel=stable|rc` and `KIT_CHANNEL`; the default is `stable`. On stable an RC is never offered; a newer RC is only named, together with how to opt in.
- **Exit codes:** 0 = up to date, 1 = update available, 2 = cannot tell (unreachable repo or no tags).
- **Also fixed:** with no release tags, `--check` ended silently with exit 1 (pipefail on an empty tag list).
- **Tests:** 7 offline fixture tests, including the card's fixture (`v1.17.0` / `v1.18.0-rc.1` / `v1.18.0`).

### F09 — Test automation

An e2e job that requires no external API key must run on PRs and be added to the required check list. E2e must have an explicit offline mode; the test result must publish pass/fail/skip counts. F01–F06 fixtures must enter regression coverage. Real scanner smoke tests must check version/adapter compatibility in a separate job; a missing toolchain must not count as a passing test there.

### F10 — Install / rollback

Default, custom hooksPath and pre-commit framework fixtures must be prepared. Existing integration must not be silently disabled; a concrete install plan including `--skills-only` must be shown. An idempotent rollback/uninstall path that records the changes the kit made must preserve existing config and user hooks. A fresh install must not require needless extra interaction; a decision should be required only on a real conflict.

**Status — 2026-11-03:** implemented on `dev/plugin-readiness`.
- **Existing hooks:** hooks the repo already has are chained, not silenced. This covers `.git/hooks`, a custom hooksPath such as `.husky`, and the pre-commit framework. Generated wrappers in `.git/security-audit-hooks/` run the kit's hook first, then the repo's own, with the same arguments and stdin (stdin only for hooks git feeds through it, such as pre-push). A failing user hook still blocks.
- **Plan and questions:** install prints what it found and what it does. It asks no question, because chaining leaves no conflict to decide. The pre-commit framework case also names `--skills-only` as the alternative.
- **Record and uninstall:** a record in `.git/security-audit-install.state` drives an idempotent `--uninstall`. Uninstall restores the previous hooksPath and removes the wrappers, unedited skills, and the agent hook entry if install added it. It keeps the config, edited skills, the scan record and the kit.
- **Older installs:** an install made before the record existed is recognised by the kit's hooksPath, or by a skill identical to the kit's template.
- **Tests:** 15 e2e checks. Fixtures: `.git/hooks`, husky-style hooksPath, pre-commit framework, fresh install, legacy install.

### F11 — Kit threat model

Data/privilege flows must be mapped for config, scanned code, scanner output, AI instructions, cache, vendor and external registries. It must be stated explicitly that the config is executable. A read-only source + separate writable artifact mount must be tested with at least gitleaks and trivy fixtures. If compatibility breaks, the migration cost must be recorded; an unverified risk must not be presented as an exploit.

**2026-10-11 acceptance addendum:** The privilege to run scanners and the privilege to execute the target's build/test code must be documented separately. The presence of Docker alone does not count as sandbox evidence. Threat scenarios must be added for repo/config/scanner text turning into agent instructions, artifact write ownership and secret environment variables. F28's first pilot does source-only review; R05 only generates a PoC. If executing target code is proposed in the future, network/environment/write/resource limits and safe artifact acceptance require a separate design and negative tests; this card does not open an execution feature.

### F12 — AI decision quality

**F12a — Keyless preparation (L1d i/ii):** The current prompt/skill/rubric difference and whether confidence is P(REAL) or confidence in the decision must be documented. A dev-only candidate contract must be prepared while preserving past prompts/results; the 31 dev + 36 holdout counts must be reported automatically. The grader must separate threshold-cost, abstention and provider errors with synthetic inputs. Brier only when the variable's meaning is clear; ECE must be reported if there is sufficient distribution. The absence of an API key does not block this preparation.

**F12b — Measurement (L1d iii/iv):** Compare current/candidate on the same split and data version; record prompt hash/model/run identity. An accessible backend such as GLM can give an early signal; no shipped skill or threshold change should come out without measurement on the product's default backend. Provider errors must not be mixed into decision quality. Different splits/versions must not be aggregated under a single score. This planning round does not start paid runs.

**F12c — Product contract:** After F12b, validate a candidate that records missing context as UNCERTAIN and does not put it into the automatic FP allowlist. Skill and grader should use the same decision set; REAL recall, precision, abstention and evaluated case rate should be tracked together. After development with new dev cases, the frozen prompt should be validated with new blind cases. **A change to the 0.7 threshold was not planned on the basis of current data.** Deep/AI-review and instruction injection embedded in output are separate sub-eval scopes.

**F12 measurement note — 2026-09-10:** The calibration scorer was added to `score.mjs` (Brier, ECE, reliability table, 0.7 threshold cost). `grade.mjs` was not touched; past runs are comparable. The first measurements were completed on two backends:

| Split | Backend | n | Precision | Recall | F1 | Brier | ECE | suppressed REAL | noise FP |
|---|---|---|---|---|---|---|---|---|---|
| dev | Qwen 3.7 Max | 31 | 100.0% | 93.3% | 96.6% | 0.4374 | 0.4484 | 0 | 0 |
| dev | GLM-5.1 | 31 | 100.0% | 93.3% | 96.6% | 0.4305 | 0.4355 | 0 | 0 |
| holdout | Qwen 3.7 Max | 32/36* | 100.0% | 100.0% | 100.0% | 0.3399 | 0.3422 | 0 | 0 |
| holdout | GLM-5.1 | 36 | 94.7% | 100.0% | 97.3% | 0.3832 | 0.3853 | 0 | 1 |

*In the Qwen holdout, 4 cases could not be scored due to a provider quota error (429); the remaining 32 cases were scored with `EVAL_ALLOW_PARTIAL=1`.

**Finding 1 — Decision accuracy is high, calibration is poor.** Both models produce ~97% accuracy and 93%+ recall; they miss the same cases and catch the same cases. This indicates the prompt is the determining factor and model choice does not change the decision boundary. However, both models give ~96% average confidence while the actual REAL rate is ~50% — ECE in the 0.34–0.45 range (good calibration should be <0.05). Confidence carries no discriminative power: correct and wrong answers get the same confidence.

**Finding 2 — The 0.7 threshold is currently ineffective.** In both models suppressed REAL = 0 (the threshold suppresses nothing) and noise FP ≈ 0 (no FP leaks above the threshold). The models already correctly recognize FPs as FPs; the threshold is functionally redundant but not harmful. A threshold change (F12c) is not urgent right now.

**Finding 3 — The confidence definition is ambiguous.** `triage_prompt.md` says "assign a confidence in [0,1] that this is a real, exploitable issue". The models interpret this as "confidence in my decision", not as P(REAL). The prompt's ambiguity is the root cause of the calibration error — not a model error. This definition must be clarified within F12a.

**Finding 4 — NVIDIA NIM GLM-5.2 end-of-life.** The `z-ai/glm-5.2` model reached EOL in August 2026 (410 Gone). GLM measurements were done via DashScope Standard with `glm-5.1`. `promptfooconfig.nim.yaml` no longer works; `promptfooconfig.glm-ds.yaml` is the new GLM config.

**Decision:** The calibration fix is **not urgent**. The product currently works on decision accuracy; confidence's discriminative power only becomes a problem when a product feature that relies on confidence ships (prioritization, JSONL event store, incremental triage). The confidence definition must be documented in F12a and solved with a prompt revision in F12c. Target: holdout ECE < 0.15 after the revision.

**Infrastructure note:** `run.sh` was switched to a write-to-temp-then-move pattern — a failed run no longer destroys the previous artifact. `score.mjs` correctly parses outputs with a thinking/reasoning prefix (Qwen, GLM chain-of-thought) via `extractJsonBlock()`. `promptfooconfig.qwen.yaml` (Qwen 3.7 Max) and `promptfooconfig.glm-ds.yaml` (GLM-5.1) are the new backend configs.

**2026-10-11 acceptance addendum — decision semantics:** F12a/F12c must separate a candidate refuted by evidence from a candidate left unresolved due to missing context. For `UNCERTAIN`, the concrete missing information and the next safe check must be recorded; a never-validated candidate must be a separate state. FP/allowlist automatic side effects must not occur in these states. While the scanner severity is preserved, the AI impact verdict must be a separate field. Deployment controls not visible in the source, wrong source traces and hardening-only examples must be added to the F12b measurement. Until the confidence definition is resolved, past Brier/ECE values do not prove calibration quality or model superiority; the 2026-09-10 inferences above are historical observations. The threshold, decision set or production prompt do not change in this planning round.

### F13 — Data flow disclosure

For each command, local computation, internet need and the types of data that may be sent to an external service must be listed. Landing meta/comparison, the READMEs and the HTML footer must carry the same limitations. An absolute claim like “Nothing leaves” must be used only for a component that actually guarantees it. If no real traffic measurement is done, the table must say it is based on a code/tool-contract review.

### F14 — First use and coverage

A new user must be able to complete the `doctor → scan → understand the result → next step` flow via a quick start. Help must show each command's dimensions, prerequisites and gate behavior. Dimensions outside `all` must be explicit in the coverage summary. If profiles are added, existing defaults must be preserved. Time to first report and coverage misinterpretations must be measured with at least a few real users; targets must be finalized after a baseline measurement.

**Addendum — 2026-11-02 (performance and UX evaluation):**
- At the end of every scan, a one-screen closing summary must be printed: dimension, status, duration, short reason, followed by "NOT inspected", "BLOCKED" and the suggested next step.
- If Docker is not running, the hook may still pass, but a single clear line must state which dimensions were not inspected and how to fix it. Because install day and push day differ, this warning must not be left only to `install.sh`.
- When the hook blocks a push, the following must be written: which dimension, how many findings, the first file:line, the raw log path and the options (fix / time-limited allowlist / `/sec-triage` / `--no-verify`). In the `error` state, the message must say "the scanner failed, this is not a finding; do not add it to the allowlist".
- Only `say`/`warn` lines and findings should go to the screen; the full raw output should stay in the log. `SCAN_VERBOSE=1` must bring back the old behavior.

**Split — 2026-11-02:** With this addendum F14's effort went above M, so it was split into two parts:
- **F14a (3b):** coverage and closing summary, help, quick start, the Docker line and the "error ≠ finding" block message. Can be done right away with F02 data. For per-dimension duration, the `seconds` field to be added to `summary.json` `dimensions[]` was moved here from F20; an additional field does not break the schema. So 3b does not wait for F20 at slot 10.
- **F14b (10, with F31b):** quiet screen output (`SCAN_VERBOSE`) and the "first file:line" in the block message. Since hooks run with `SARIF=0`, showing the first finding requires parsing each tool's raw output. It is the same work as the F31b infrastructure that moves dimension outputs into separate files.

**F14a status — 2026-11-02:** implemented on branch `feat/f14a-closing-summary`.
- **Closing summary:** each dimension's status, duration and reason; dimensions the command does not cover ("not in 'all'"); if Docker or uvx is missing, a single line stating which dimensions were not inspected and how to fix it.
- **Block message:** whether it is a blocking finding or a crashed scanner is written separately. For a finding, the options are listed; for a crashed scanner, it says "not a finding; do not allowlist it".
- **`scan.sh help`:** commands, gate labels, prerequisites, what is outside `all` and the first-use path.
- **Duration:** per-dimension `seconds` was added to `summary.json`. It is not copied into evidence, so evidence's determinism is preserved.
- **Hooks:** dropped their own messages that guessed the reason. For example, pre-commit said "secret in staged changes" even when gitleaks crashed; now they point to the closing summary.
- **Output contract preserved:** the `── run:`, `NEXT STEP`, `NOT inspected`, `BLOCKED` lines remain.

**Not done:** the measurement with real users the card asks for (time to first report, coverage misinterpretations). This needs real users; the measurement remains open.

### F15 — Landing quality pass

Narrow/wide screen, keyboard, basic screen reader flow, use with JS disabled and clipboard denial must be verified in a browser. Critical content must stay visible on a JS error; the copy result and error must give an accessible notification. Existing reduced-motion support must be preserved. The design must not be changed merely to complete a checklist for problems that were not found.

### F16 — Full evidence coverage

**F16a validation:** A command → native output → evidence → HTML/SARIF matrix must be published. The third trivy/uv.lock suppression path left open in old plan #12 must be validated with the relevant advisory/package fixture; it must not be assumed that the same CVE exists in every tool. **F16b adapters:** pip-audit, JS audit, checkov and GuardDog adapters must be implemented as separate small items. Each adapter must be tested with clean/with-findings/erroring native fixtures. For a dimension with no output, missing evidence must be shown instead of “0 findings”. The severity source must be preserved and CVSS must not be fabricated.

### F17 — Modular maintenance

First, the status/exit code/output contract must be pinned down. Adapters, discovery and artifact management must be extracted into separate modules with small PRs; CLI compatibility must be preserved. If there is a Bash 3.2 target, each step must be tested against it. If modularization would introduce a new runtime dependency, its benefit must be measured separately.

**Slice 1 — dimension registry and adapter contract (2026-11-03, implemented on `dev/plugin-readiness`):**
- Two text tables in `scan.sh` (`DIM_UNITS`, `SCAN_COMMANDS`) replace the dispatch `case`. Each unit records its record name, adapter function, gate class and toolchain need. Each command records its units in run order and what it leaves out. `run_scans`, the help line "not in 'all'" and the closing summary read these tables. No `scan_*` adapter was changed. The tables are plain text because the code must still run on Bash 3.2.
- The contract is in `docs/adapters.md`: return codes, status helpers, SARIF location, and the rules guarded by e2e.
- e2e has two new static checks. The first verifies that every unit names an existing function with valid values and that every command's units are registered. The second verifies that `run_scans` is the only dispatch site.
- Behavior is unchanged. The old and new `scan.sh` were run on the same fixture with shimmed docker/uvx/npm, covering 13 commands, `bogus` and `help`, each in five scenarios: clean, findings, scanner error, no docker, no uvx. The 75 normalized outputs and `summary.json` files were identical. A deliberately reordered registry was caught in all 10 affected cases. The offline e2e run gave 243 passed and 0 failed.
- **Naming:** the F16b "adapters" are native-output → evidence normalizers. They are a different layer. They attach to the same registry as an extra column (a SARIF or normalizer per unit) and need no second dispatch.
- **Next slices, as needed:** move the image and tool pins used by `warm` and provenance into the registry; have `doctor` read the `needs` column; declare each unit's SARIF file name.

### F18 — Platform and paths

Automated Linux and macOS smoke tests; for WSL2 there must be an actually executed result or an explicit “not verified” state. The minimum Python version must be documented. Repo and file paths containing spaces/Turkish characters, worktrees, unborn/shallow repos and deleted/renamed files must be tested. Arguments split on spaces must be moved to array/NUL-safe handling.

### F19 — Finding / decision lifecycle

A line shift must not needlessly reopen the same finding; two different packages with the same CVE in the same manifest must not be lost. Fixtures must be prepared for package identity and tool fingerprint. The decision record must carry owner/rationale/due date/verification conditions. The alias mapping source and applicable scanners must be specified; an ambiguous match must not produce automatic suppression. A backward compatibility/migration design must be done. The JSONL event history left over from T3.1 and the Phase A SQLite/checkpoint idea are a conditional continuation of this model: two separate persistent storage systems must not be added without measuring the re-run cost of interrupted long AI runs; if needed, start with a single format and test crash/resume and idempotent replay.

**UI track — 2026-11-03:** F19a is taken directly after F26, as a prerequisite of the R13 local UI. Only the identity and decision-record contract moves. F19b (schema validation, output migration) stays in slot 9. R13a reads the F19a record, and R13c's allowlist approval writes it through the CLI.

**2026-10-11 acceptance addendum — structured AI evidence:**

- F19a delivers the identity/decision contract, F19b schema validation and output migration. Source reference and dirty state, root cause, ordered source trace, applicable controls, preconditions, affected asset, decision rationale and verification blocker must be mandatory in the branches where they are needed. F19's current rough effort is re-estimated with this scope during design.
- Scanner record, AI decision, suppression policy and verification state must be separated. `REAL → confirmed`, `FP → rejected`, `UNCERTAIN → needs_validation` are not assumed to be automatic and lossless equivalences; old records are migrated with their evidence, fields without evidence are not fabricated.
- When the source/preconditions change, the old decision must be re-reviewed. An old FP must apply only to the same refuted claim; it must not remove the whole component from scope. There must be fixtures for line shift, a changed control, different decisions for the same root cause and the same CVE in two packages.
- It must be decided explicitly whether the current Markdown write source is kept, or whether to move to a schema-based decision record and generate Markdown. Two independent write sources are not created. The migration is documented with F25; HTML/SARIF are derived from the same validated model.
- The validator must check for a missing source trace, invalid path/line, conflicting decision fields, duplicate identities and size limits. Schema success does not prove the finding is correct; F28 checks source claims separately. Old schema/renderer behavior must be preserved with migration fixtures.

**2026-11-03 acceptance addendum — epistemic status (Masriyan comparison, local note `docs/compare/masriyan-cybersecurity-skill.local.md`):** The decision record must carry the type of evidence in a field separate from the decision: `observed` (tool output or source line), `inferred` (reasoning over a path), `unverified`. This makes visible which evidence REAL and FP rest on. An `inferred` REAL must still carry the sink, source and path triple; the epistemic field does not loosen the evidence bar. Because Masriyan's license adds attribution terms on top of MIT, only the idea is taken; no text or code is copied.

### F20 — Measure first

Per-dimension duration, status reason, coverage and cache hit information must be produced locally. Warm/cold runs must be separated on small repo, monorepo and large history fixtures. Secret data or source code must not enter the metrics; network telemetry must not be added by default. A measured bottleneck list must be produced for F21.

**First measurement — 2026-11-02:** On the kit's own repo (82 files, 89 commits, macOS + Docker Desktop, images pre-pulled) each step was run 3 times. Warm run times: secret ~1 s, sast ~3 s, container ~36 s (cold 111 s), sbom ~3 s, `all` ~40 s, evidence/report < 0.5 s. The bottleneck is the trivy DB download; moved to F30. The per-dimension `seconds` field was moved to F14a (additional field, does not break the schema); F20 uses it for measurement. This measurement is for a small repo; monorepo and large history fixtures are still needed. In one run a non-reproducible rc=2 was seen. Possible cause (not verified): during the measurement, F03 changes were half-done in the same working tree (`lib/evidence.py` was being edited, `scan.sh checksums`/`verify` were running). It must be re-measured on a clean tree after F03 is merged; if seen again, it must be investigated.

### F21 — Cache / monorepo

**F21a = R5.2 slice B:** Only the dimension cache is delivered. **F21b = R5.4:** uses F21a's validated input-hashing infrastructure; delivered separately if there is a real monorepo bottleneck. F21b does not hold up F21a's release. Correct invalidation must be shown when code/lockfile/config/rules/tool/advisory freshness changes. Runs with the cache on and off must produce the same result over the same scope. Shared monorepo lockfile and shared component changes must not escape a subtree scan. The gain must be reported against the F20 baseline; a speed win must not be accepted before correctness is ensured.

### F22 — Single planning source

**Done — 2026-09-08:** A single current order with F and R identities was created, pointers to the old roadmaps/plans were added, completed items and remaining conditional ones were recorded in the mapping document. Historical notes are preserved. R5.2 slice A is recorded on local main and as Unreleased in the local CHANGELOG; the remote release state was not verified. No GitHub issue/PR was created. When moving to actual development, person/date and remote release state are updated separately.

### F23 — Unit test infrastructure for Python modules

**Done — 2026-09-14:** Direct tests under `tests/unit/` and a CI pytest job exist for the four Python modules under `lib/` (`evidence.py`, `kit_sarif.py`, `pkgcheck.py`, `report_html.py`). 234 tests passed locally. In RC.1 the pytest job did not start during action resolution; the pin error unrelated to the test code was fixed in RC.2. F09's remote required-check enforcement remains open separately.

**Acceptance criteria:**

- A pytest-based test infrastructure must be set up in the `tests/unit/` directory for the `lib/` modules; no external dependency must be added (stdlib + pytest only).
- A `pytest` step must be added to CI; it must be one of the required checks of the F09 PR gate.
- For each module at least the following scenarios must be tested: `evidence.py` — severity normalization table (CVSS bands, SARIF level, tool default), dedup logic, missing/broken SARIF behavior; `report_html.py` — HTML escape, missing `exit_code` state (linked to F04), zero-finding output; `kit_sarif.py` — empty finding list (must not be written), suppression rendering; `pkgcheck.py` — install command parsing, block/report classification.
- Fixture data must be kept under `tests/fixtures/` as synthetic SARIF/JSON files; real scan output must not be used.
- Tests must be able to run with `PATH=/usr/bin:/bin:/usr/sbin:/sbin` (without external tools).
- Must be delivered in the same PR as F09 or right after it; when the F01–F04 fixes arrive, each must come with the relevant unit test.

### F24 — Config file validation and safe sourcing

The `.security-audit.conf` file is loaded with `source` in `scan.sh` (`scan.sh:48`). This means the file is executable bash code — part of the threat model described in F11. Currently, a syntax error, an invalid variable assignment or an unexpected command line produces no meaningful error for the user; the scan can silently continue with wrong values.

**Acceptance criteria:**

- The `scan.sh doctor` command must resolve the active config; it must warn if it contains an unrecognized variable, a syntax error or a dangerous command (such as `rm`, `curl`, `eval`).
- Each variable in the config must be compared against the known variable list (generated from `security-audit.conf.example`); an unknown variable must be reported as `WARN`.
- The config file must be added to the scope of `scan.sh verify` — structural deviation from the example file (missing required field, type mismatch) must be detected.
- A config validation failure must not block the scan (fail-open is preserved); but a warning banner must be printed and recorded in `summary.json`.
- The `security-audit.conf.example` file must be updated with every new config variable; CI must check the consistency of the example and actual config schema (an assertion to be added to the F09 test gate).
- Must be delivered together with or right after F11; when the F11 threat model documents the executable nature of the config, F24 provides the concrete check that references that document.

**Status — 2026-11-03:** implemented on `dev/plugin-readiness`.
- **The check:** `config_check` runs on every scan and reports, as warnings:
  - a syntax error (`bash -n`);
  - an unknown setting, against the names in `security-audit.conf.example` plus the env knobs SARIF/REPORT/BASE_REF/SKIP_SECURITY;
  - a line that runs a command;
  - a command substitution in a value;
  - more than one statement on a line;
  - wrong types on the values in force: integer waits/TTLs, and the sets for `SCAN_OFFLINE`, `SARIF`, `PKGCHECK_CACHE`, `REPORT`.
- **Where warnings appear:** fail-open. They show in the closing summary and `summary.json` `config.warnings`, and in full in `doctor` and `verify`; `verify`'s exit code is unchanged.
- **CI consistency:** an e2e assertion that every `VAR="${VAR:-…}"` setting in `scan.sh` appears in the example. Env-only and internal names are listed in the test.
- **"Required field" deviation:** not applicable. No setting is required; every one has a default.
- **Tests:** 9 e2e checks. Two real consumer configs raise no warning.

### F25 — Version upgrade guide and breaking change notice

Consumers update versions with `bootstrap.sh`, but breaking changes between versions (evidence schema change, removed command, changed config variable, new required tool) are written only in the CHANGELOG. `bootstrap.sh --check` reports that there is a new version but does not say what changed or what the consumer must do. Once the F08 channel split is done, the RC/stable distinction will be clear; but a guide is missing for upgrades between stable versions too.

**Acceptance criteria:**

- In every release PR, in addition to the CHANGELOG, a `MIGRATION.md` or an **upgrade notes** section embedded in the CHANGELOG must be prepared. This section must list only breaking changes and required consumer actions.
- `bootstrap.sh --check` output must summarize the breaking changes between the current `.kit-version` and the target version (extracted automatically from the CHANGELOG or read from a hand-written `UPGRADE-NOTES` file).
- When the evidence schema version (`security-audit-kit/evidence@1`) changes, what happens to the old `evidence.json` file must be documented; if a migration script is needed, it must be delivered in the same PR.
- For removed or renamed `scan.sh` commands, a deprecation warning must be given for at least one version; once a command is removed, calling the old name must redirect to its new counterpart.
- When `install.sh` is re-run, it must show the version difference before overwriting the config file (overlaps with F10).
- Must be delivered in the same delivery slice as F08 (slot 4) or right after it; must be ready before the first stable release.

**Status — 2026-11-02:** implemented on branch `feat/f25-upgrade-notes`. Delivered before F08 because it was moved to 3b.
- **Upgrade notes mandatory:** the `### Upgrade notes` section in the CHANGELOG is now mandatory; `release.sh rc` does not cut a tag for a version without the section. If there are no changes, `- None.` is written.
- **`bootstrap.sh --check`:** shows the notes between the pin and the latest final version, labeled by version. It reads the notes from the target tag's CHANGELOG with a single-commit shallow fetch. An RC pin also gets the notes of its own final version.
- **When `install.sh` is re-run:** it does not touch the config; it lists new settings by name.
- **Policies:** the deprecation policy for commands and settings and the schema versioning rules were written into RELEASING.md. A "Versioning" section was added to the evidence and summary schema docs.
- **Old evidence.json:** not migrated in place; regenerated on the next scan. So no migration script was needed.
- **Also fixed:** after a final was published, `--check` suggested an older RC of that version as "latest" (because of `sort -V` ordering).

**Not done:** there is no removed or renamed command or setting today. So no deprecation mechanism was built; it will be added per the policy at first need.

### F26 — Serverless HTML report usability

**UI track — 2026-11-03:** F26 is the first step of F26 → F19a → R13. It stays the zero-install view: a file that opens without a server. Its escaping and rendering are written so that the R13 local UI can reuse them instead of building a second renderer.

Builds on the existing `lib/report_html.py` and `evidence.json`. The goal is to meet the first visual-use need with a small delivery; not to rewrite the scanners or the AI runner. As P2 it is taken up after the reliability deliveries, as a continuation of the F14 first-use flow. The F04 correct report contract is a prerequisite; F16's coverage/gap display is used. The F19 decision write model and the F21 cache are not prerequisites for this read-only view.

**Acceptance criteria:**

- A single HTML file opens via `file://`; it requires no server, database, external CDN/font, frontend build system or new runtime dependency.
- Text search; severity, tool and decision filters; expandable finding/evidence details are provided. The filtered count is distinguished from the total; there is a reset-all-filters option.
- Run identity/date, scanned and skipped/erroring dimensions remain visible. “No findings match the filter” does not mean a clean scan.
- Findings are readable with JS disabled; keyboard use, narrow screens and printing are supported. Existing HTML escaping is preserved; finding text is not inserted as executable HTML.
- The existing report command and offline output are preserved. Filter correctness with synthetic findings, malicious text and missing-evidence cases are checked; ease of reaching a finding in real first use is evaluated with F14.

### R01 — Remediation compute scope decision

First evaluate, over one direct, one transitive and one parent-range-blocked example, whether a suggestion can be produced with the existing skill's read-only commands. If sufficient, the task closes with a command/procedure clarification; no resolver product is written. If not, produce a helper design starting with a single ecosystem; the manifest/range/fix version source should be shown as evidence. Installing packages, running build scripts or blind force-pinning must not be automatic steps. Expansion to other ecosystems is estimated separately. The decision is independent of F16; a helper bound to the normalized finding depends on F16.

### R02 — Skills-only trial channel

First write the contract for repos with/without a vendored scanner and for a different working directory. The plugin must not download the kit automatically or silently change hooks/config; it must produce a clean prerequisite explanation for a missing scanner. Manifest, version, root resolution and permission declaration must be tested on the target host; `allowed-tools` must not be presented as a sandbox guarantee on its own. The deterministic scanner stays vendored+pinned. Opening the Claude channel does not require full Phase B; support for other hosts needs separate demand and testing.

**Priority change — 2026-11-02:** Raised from P2 candidate to P1; moved from 11 to 8 in the delivery order, directly behind F10. Rationale: distribution is the main bottleneck. The repo got 0 stars in 4.5 months, and the kit is in no plugin marketplace. There are direct competitors in the same channel: Semgrep's official Claude Code plugin (MCP + hook + skill, scans every file the agent produces, in the `/plugin` Discover tab; requires a Semgrep account) and Trail of Bits' `static-analysis` plugin (CodeQL + Semgrep + SARIF merging). As differentiators, the kit's pinned/checksummed supply chain, the `skipped ≠ pass` status contract, the pre-install `pkgcheck` hook and not requiring an account should be highlighted. Acceptance criteria unchanged; a one-command install via `.claude-plugin/marketplace.json` is the target, vendoring with `bootstrap.sh` stays as an option.

**2026-11-03 acceptance addendum (Phoenix (local note `docs/compare/phoenix-security-skills.local.md`) and Masriyan (local note `docs/compare/masriyan-cybersecurity-skill.local.md`) comparisons):** All three competitor tools are in a marketplace; the distribution gap was confirmed by the comparison. `claude plugin validate --strict` must run in CI. Manifest-to-disk consistency must also be tested: every skill, hook and command path in the manifest must exist, but there must also be no skill that is not in the manifest. Hooks must come with the plugin's `hooks.json` file; the user's `settings.json` file must not be merged. Phoenix's `jq` merge overwrites the user's existing hook arrays; the same bug must not be repeated.

### R03 — Heavy reachability pilot

Go call-analysis will not be rewritten. If there is a concrete triage cost in Python or JS, pilot on a single stack; measure install/duration and validated benefit. Do not automatically drop findings marked “not called” from the gate. Build script execution requirements, offline limits and output scope should be documented explicitly. The pilot should use F21a cache correctness and the F16 adapter contract; if there is no benefit, the integration is closed.

### R04 — Provider independence / local triage

Two separate products should not be built: first measure the triage quality of the needed candidate in the existing harness, and design a small opt-in runner only for an accepted candidate. Uncertain results should be escalated to a strong backend; in a real air-gap where escalation is not possible, they stay UNCERTAIN. Full agent loop/MCP/tool policy work is opened only if the triage pilot does not meet the need, and is estimated separately. Deep review is not handed over to an unmeasured local model; model size alone is not evidence of quality. If the need for R10 extraction arises, it becomes part of this program.

### R05 — PoC generation

Only for an explicitly selected finding, generate preconditions, synthetic data and a repro artifact for human review. There must be no automatic execution, requests to a live target, or a “generated = verified” decision. Generated evidence and human-verified evidence should carry separate states. A general PoC engine should not be opened without quality measurement and a relationship to the F19 identity.

### R06 — Python hash-pin decision

Work out the update cost of platform/tool dependency locks against the integrity need identified in F11. Compare current on-demand use with a small hash-verified tool pilot. If the decision is accepted, refresh, hash mismatch, platform support and offline cache tests are designed together; this card is not an order to convert all tools directly.

### R07 — Publisher identity

If the consumer needs independent signature verification, design an identity/issuer/version verification policy. Good signature, wrong publisher, wrong artifact and missing verification service should be tested. Pins and CHECKSUMS are preserved. Setting up key/OIDC infrastructure or publishing is not part of this plan update.

### R08 — Situational static coverage

Scorecard/conftest/modelscan are old research candidates, not selected dependencies. Nothing is added until a concrete consumer need, a gap in the existing tools, current license/pin, internet/token and maintenance cost are verified. The selected tool conforms to the F02/F16 contract. Nuclei/DAST is out of scope for this card; the old “maybe” was closed by a later out-of-scope decision. Since 2026-11-03, an opt-in external form of it is tracked separately as R16.

### R09 — Wizard, last

The earlier user preference is kept: after the priority active work is done, the existing mock is re-evaluated against the command/coverage/report contract of that day. It does not mean waiting for all indefinitely deferred ideas to be done. Explicit `wizard` entry, no-arg/headless compatibility, EOF/back/NO_COLOR/ASCII/TR-EN and missing-tool explanations are tested. No new dependency or automatic tool installation; F14 core UX fixes do not wait on the wizard as a justification.

### R10 — Skill extraction

Not opened on the grounds of continuous token savings. If there is an R04 consumer or a measured maintenance problem, tables/procedures are split out first; the evidence bar and judgment rules are not moved to an optional reference that may fail to load. Reference discovery and product behavior are tested on the host; the F12 quality gate is preserved.

### R11 — Tool pin update automation

The kit pins 7+ external tools (gitleaks, trivy, syft, osv-scanner, semgrep, checkov, pip-audit, guarddog, zizmor). Version/digest updates for these tools are fully manual; there is no Dependabot/Renovate integration. Over time, old versions create a risk of security vulnerabilities, incompatibility or performance loss. The `*_VER` / `*_DIGEST` variables at the top of `scan.sh` are the single update point, but after an update, regenerating `CHECKSUMS`, self-audit and e2e runs are triggered manually.

**Acceptance criteria:**

- A checklist or GitHub Action must be prepared for pin updates: version change → regenerate `CHECKSUMS` → `scan.sh verify` → e2e → self-audit → PR.
- Instead of Dependabot/Renovate, a lightweight kit-specific `scripts/check-pins.sh` can be written; it must query each tool's upstream release and compare it to the current pin (GitHub API, PyPI JSON, Docker Hub). Since it needs network access, it must run as a scheduled CI job (weekly).
- If the update PR is opened automatically, the dogfood checklist (the list in RELEASING.md) must be mandatory in the template.
- For Docker digest updates, `docker manifest inspect` or an equivalent path must be used; a digest change without a tag change (tag-repoint) must be caught by the existing guard.
- Pin updates must be tracked in the CHANGELOG under `### Changed`; which tools were updated must be visible in the version the consumer gets via `bootstrap.sh`.
- After the R06 (Python hash-pin) decision, the same mechanism must be extended to the Python tools too.
- **Opening condition:** when 3+ tool versions fall 2+ minors behind upstream, or a security notice (CVE) is published for one of the pinned tools. Prioritized after the F07 release gate and the R06 hash-pin decision are done.

### R12 — SkillSpector pilot and optional integration

The security of skill packages loaded into the agent is a concrete candidate that complements the existing application SAST/SCA and `sec-ai-review` coverage. It is tracked on this card separately from R08; no second general scanner card is opened for the same work. Sources: [SkillSpector README](https://github.com/NVIDIA/SkillSpector) and [package definition](https://github.com/NVIDIA/SkillSpector/blob/main/pyproject.toml), reviewed 2026-09-14. Static and optional LLM analysis and JSON/SARIF outputs exist; Python 3.12+ and the LLM/YARA dependencies support the requirement for an isolated install. Before implementation, the license, dependencies and output contract of the selected commit are re-verified. The tool was not installed or run in this planning round; there is no quality measurement.

**R12a — Pilot (S):** After F26, with the F11/F13 data and trust boundaries, static scanning is measured with a fixed version/commit on the kit's `skills/` content and synthetic benign/malicious skill fixtures. In particular, false positives on security skills that describe attack examples, misses of known bad examples, duration and install cost are recorded. Fixtures stay scanned data; the instructions in them are not executed. The pilot's measurable acceptance thresholds are written before the run; with insufficient benefit the integration is deferred. This separate pilot does not require all F16 adapters to be finished.

**R12b — Adapter (M, if the pilot succeeds):**

- The proposed `scan.sh skills` entry is optional; the first version is not added to `all`, pre-push or the automatic install gate. The command does not exist yet.
- The tool runs in a separate, pinned environment; Python/LLM dependencies are not installed into the kit's base install. Missing tool, missing target, error and finding states are separated per the F02 contract.
- The initial scope is explicitly selected skill directories inside the repo; the user's global skill/config/env files are not scanned automatically. A skill is handled together with its associated package files, not just `SKILL.md`.
- The default is `--no-llm`; using an external model is an explicit choice. Static analysis is not presented as fully offline: network/data behavior including OSV is written into F13.
- JSON/SARIF results are normalized via F03/F16 into the same run's `evidence.json` and HTML output. Tool/rule, file/line, scan mode and original risk information are preserved; the risk score does not replace CVSS or the kit's REAL decision.
- Reporting only at the start. The baseline is not bulk-accepted automatically; a pre-install/hard gate is opened only with a separate policy decision and a false positive/miss measurement. If LLM mode is added, quality and uncertainty are evaluated separately with F12.

### R13 — Local UI that starts scans (planned, after F26 → F19a)

**Direction — 2026-11-03 (user decision):** No longer conditional. As the product grows, it needs control a static report cannot give: new vs resolved findings, approving a time-bound exception, seeing expiries and starting a scan. The UI track is **F26 → F19a → R13**. F19a comes first because, without a stable finding identity, a line shift shows the same finding as new and the UI would be wrong about the one thing it exists to show. Shape:
- `scan.sh ui` starts a localhost server built only on the Python standard library. It adds no new dependency and no install step. This settles the framework question left open below.
- **R13a — read-only:** run history, coverage (including skipped and indeterminate), and findings with their evidence and decisions, read from `summary.json`, `evidence.json` and the F19a decision record.
- **R13b — run a dimension:** the first slice described below.
- **R13c — approve a time-bound allowlist entry:** an expiry is mandatory. The UI does this through a CLI command, never by writing the file itself.
- The UI is only a thin client over the CLI. Everything it writes shows up as a `git diff`, and it never commits. The gate decision always stays with the CLI and the hooks.
- The static F26 report stays the zero-install fallback and shares its escaping and renderer with the UI.

This supersedes "no writing suppressions from the UI" below. That rule now holds only until R13c, which requires F19a. The opening condition below, and the ordering after R12, no longer apply.

Original record: opened if the F26 report does not meet daily use and the user shows a concrete need for starting scans/tracking progress. The default plan order is after the R12 pilot decision; SkillSpector integration is not a technical prerequisite, and if the pilot is dropped the UI is not blocked. CLI and hook/CI behaviors remain the shared execution path.

**First slice:** Single repo, single active scan, fixed coverage options, start/status/log/result screen. A small local Python service calls the existing `scan.sh` commands; the screen reads the shared evidence output. The framework choice is made during implementation. The first version has no central hosting, user management, multi-repo panel, database, or writing suppressions/fixes from the UI.

**Acceptance criteria:**

- F01–F05 run isolation, cancel/error and last-completed-result separation are verified. A live run and an old result are not shown as the same scan.
- The service binds only to loopback; Host/Origin and session token checks prevent other web pages from starting scans. A fixed command/argument list is used; UI input is not concatenated into a shell command.
- The repo root is selected explicitly at startup; the API does not offer arbitrary file reads or config/env contents. The executable repo config boundary from F11/F24 is handled in the user flow; a syntax check does not count as a sandbox.
- Clean/with-findings/erroring/skipped scans, concurrent starts and unauthorized request flows are tested. The install and first-result flow is documented; optional UI dependencies do not enlarge the CLI install.
- `sec-triage`/deep review do not automatically enter UI scope. If a need to run agents arises, R04 is a separate quality/runner decision; writing finding decisions is a separate delivery dependent on F19.

F26/R13 and the R09 wizard are not automatically developed as two solutions to the same onboarding need. UI usage data re-evaluates the need for the wizard; R09 keeps its position as the last planned feature.

### F27 — Coverage ledger in deep review

The first delivery is only the opt-in whole-repo/deep flow; no agent cost is added to routine scans. The existing component/class plan is turned into a machine-verifiable coverage record bound to the run. No new DB or resume engine is needed.

**Acceptance criteria:**

- The unit identity is generated deterministically from surface, trust boundary, component and review class. Reviewed paths, the security condition checked, result, evidence, the responsible review and candidate identities are recorded; an empty “reviewed” statement is not enough.
- Planned, in-progress, completed, blocked, deferred, candidate-containing and out-of-scope work are distinguished. Skipped work does not count as clean. Unit/candidate references and state transitions are checked by a validator.
- A previous run is used only by comparing the relevant source and conditions. Changed source and unresolved blockers reopen work. The scanner cache does not substitute for AI coverage evidence.
- Coverage selection, the time/call budget and the closing reason are visible in the report. A candidate not reviewed due to the budget is not mixed up with a validated uncertain candidate; the report stays partial. If there is no budget, no artificial limit is produced.
- Fixtures: same source, line shift only, control change, scope narrowing, half-finished review, duplicate unit and an unreferenced candidate. The F04/F26 report shows the coverage gap; no new dashboard is needed.

### F28 — Independent validator and coverage check

**F28a — P2 pilot:** Using the current host's separate context/agent capability, source review of a candidate independent of discovery is measured. A new provider runner (R04) is not a prerequisite. If a separate context cannot be provided, it is recorded explicitly that independent validation was not done; self-review is not labeled independent.

**Acceptance criteria:**

- The validator identity differs from the discovery owner; it re-reads the candidate's source references and the strongest counter-evidence. Source review and executed test evidence are separated; the pilot does not run target code and does not write automatic fixes/allowlists.
- The final decision conforms to the F19 schema. A validation error or budget exhaustion does not produce a positive decision. Only the coordinator writes the shared artifact; reviews return isolated results. A material source/decision change requires a new check.
- The pilot is compared with the current sweep on the same versioned data/split as F12: REAL precision/recall, abstention, completion rate, calls/tokens and duration. There must be negative examples of wrong location, overlooked protection, instruction injection in source text and exaggerated impact. Without API access, the pilot stays unmeasured.
- Moving to the default flow happens only with a measured benefit/cost decision. This plan does not start paid evals.

**F28b — Conditional continuation:** If F28a is useful, an independent coverage check against the F27 ledger and a final record check are added. Increasing the discovery count alone does not count as coverage success. A share of the budget is reserved for validation/closing; work that does not make it stays visible. The decision to make both checks mandatory in every routine is measured separately.

### R14 — Expert domain playbooks (conditional)

If a real consumer has a source review need that the existing skills/scanners miss, start with a single domain. Candidates: HTTP/auth protocol mismatch, RPC/queue authorization, data deletion/restore/tenant lifecycle, browser or mobile/IPC. Native/kernel/binary coverage is not an automatic product target.

For the selected domain, the entry signal, boundaries to review, non-applicability reasons, at least one real finding/FP twin and source references must be prepared. New rules must be tied to the F12 dev measurement, coverage to F27. With R10, only the needed references should be split out; the whole skill tree is not reorganized. No new scanner, live testing or exploit execution is added. If code/text is taken, the version and license are verified at implementation time and attribution is preserved.

### R15 — New vulnerability tracking, event output and agent access (note)

**Record — 2026-11-02:** Arose from a user question: can alerts be received between scans for newly published vulnerabilities in dependencies, and can the result be connected to an AI agent (MCP etc.) and alerting/observer tools. In the comparison with a commercial AI-assisted SOC platform, no new core feature to take into the kit was found: counterparts of AI triage, FP filtering, threat score and case records (`/sec-triage`, allowlist decay, KEV/EPSS, `findings-<date>.md`) already exist. A web UI on top of the CLI is already in the plan via the F26 → conditional R13 decision. This card is not critical right now; it does not change the order and is re-evaluated on the triggers below.

**Today's gap:** Scanning only runs on commit/push/manually. If a new vulnerability is published for a dependency without the code changing, it is invisible until the next scan. The weekly self-audit in the kit's own repo is not a template for consumers.

**Stages and conditions:**

- **R15a — Dependabot guide (docs):** Explains to a GitHub consumer the setup of Dependency graph, Dependabot alerts / security updates, `dependabot.yml` and auto-triage, and the division of labor with the kit (Dependabot is the continuous trigger; the kit provides reachability, KEV/EPSS, fix cost, and the guarddog/pkgcheck gate on Dependabot PRs). It does not directly increase kit usage; it answers the question “what about the gap between scans”. Can be handled together with the F14 help/coverage work. Also, the kit's own repo has no `.github/dependabot.yml`; the `github-actions` ecosystem can track SHA-pinned actions (related to R11; does not cover docker/pyrun tool pins).
- **R15b — Scheduled consumer CI template:** Daily `SARIF=1 scan.sh osv` + deps, report only, does not break the build. On GitHub, SARIF is uploaded to Code Scanning; GitHub does the tracking and notification of new/closed alerts.
- **R15c — Diff and event output:** `evidence_diff` (new / resolved / ongoing; no “resolved” for an `indeterminate` dimension, the first run is the baseline), KEV/EPSS only for new CVEs, JSONL (SIEM / SOC platforms), Prometheus textfile metrics (observer/alerting tools), optional webhook. A single queue with Dependabot alerts requires GHSA↔CVE alias mapping. The kit does not go to the network; external sending is a separate step and is listed in the F13 table. Without F03 and F19, line shifts produce fake “new” items.
- **R15d — Read-only MCP server:** `get_summary`, `list_findings`, `get_finding`, `diff_since`, `coverage_gaps`; local stdio, optional component. Starting scans and writing decisions are not exposed to MCP: finding text comes from scanned code (prompt injection, F11) and the single source of decisions remains `findings-<date>.md`.

**Opening trigger:** A real consumer's request for between-scan vulnerability notification or alerting/agent integration. Since R15a is documentation, it can be taken during F14 without waiting for a trigger.

### R16 — Optional external dynamic adapter (conditional)

**Record — 2026-11-03:** Arose from user questions on agentic pentest tools (Strix, PentAGI) and a list of 15 classic security tools. None of them becomes a `scan.sh` dimension. A dimension must be deterministic, run in seconds, need no live target and be safe to gate a hook on, and these tools are not. Strix runs exploits and has an LLM in the loop. PentAGI is a self-hosted platform with Postgres and a mounted `docker.sock`. Nmap, OpenVAS, SQLmap and commercial web proxies need a live target or attack it, and several carry GPL/AGPL/NPSL or commercial licenses. The only defensible shape is an adapter that sits outside `all` and the hooks and is called explicitly. This card reopens the Round 4 "Nuclei/DAST out of scope" decision **only** in that shape.

**Reference tool: nuclei** (to be verified when opened: MIT license, current version, digest). It is a single pinned binary or image whose templates can be limited to non-intrusive tags. It is preferred over Strix and ZAP for a first adapter because it is the furthest from "the kit attacks". Strix and ZAP baseline may follow through the same adapter shape if a consumer asks.

**Acceptance criteria:**
- The adapter is registered in the F17 registry under its own command. It is never part of `all` or `fast`, and no hook calls it.
- The target is named explicitly on the command line and confirmed. There is no default target and no discovery. A run without a target is `not_applicable`, not `pass`.
- Only non-intrusive template tags are used. An allowlist of tags is pinned in the kit, and widening it requires an explicit opt-in variable.
- Native JSON is normalized to SARIF, then to `evidence.json` through the F16b normalizer, and is then judged by `/sec-triage` under the same hard-evidence bar. Live-target findings carry a separate source marker so they are never read as code findings.
- The image or binary is pinned by digest, appears in provenance, and is listed in the F13 data-flow table, because it sends requests over the network.
- License, version and template-set provenance are re-verified when the card opens.

**Not in scope:** exploit execution, credential attacks, network/host scanning, and any tool that needs a server, a database or `docker.sock`.

**Opening trigger:** a real consumer request for a live-target check that the static dimensions cannot answer, after F16b.

### F29 — py-deps environment selection

**Finding — 2026-10-21 (V+C):** `scan_py_deps()` (`scan.sh:252`) accepts the active `$VIRTUAL_ENV` as the project's environment when the repo has no `.venv` (`scan.sh:264`). It does not check whether this variable belongs to this repo, or even whether it is a real venv. The same function's comment defines auditing another project's environment as a “silently wrong answer”; this rule is applied when the repo `.venv` exists and not when it doesn't. On the developer machine, with `VIRTUAL_ENV` pointing to pyenv's global interpreter (`~/.pyenv/versions/3.12.9`), the global interpreter was audited in a venv-less fixture containing only `pyproject.toml` instead of the expected INDETERMINATE. pip-audit raised `Dependency not found on PyPI` and the gate HARD-blocked (rc=1). The same path can also produce a false `pass` in a clean foreign environment; this second outcome is inferred from the code path and was not measured separately. Since `VIRTUAL_ENV` is not set in CI, e2e did not see this; e2e was made hermetic on the F01 branch with `unset VIRTUAL_ENV`, product behavior did not change.

**Acceptance criteria:**

- The active `VIRTUAL_ENV` must count as the project environment only if it can be tied to this repo (e.g. its path is under `ROOT`). If it cannot, the behavior must be chosen explicitly: fall back to the no-env path (static manifest read or INDETERMINATE) or accept it with an explicit opt-in variable. The choice and rationale must be recorded on the card.
- A `VIRTUAL_ENV` that does not carry `pyvenv.cfg` (not a venv) must not count as a venv.
- If an environment that does not belong to the project was audited, this result must not be reported as `pass` or a HARD finding. The output must say which environment was audited and why it was selected; the `summary.json` status must align with F02's status naming.
- Fixtures: repo `.venv` + foreign `VIRTUAL_ENV` (existing test kept), no `.venv` + foreign real venv, no `.venv` + non-venv interpreter (the pyenv global example), no `.venv` + venv under `ROOT`, `VIRTUAL_ENV` unset.
- The behavior change for existing users must be noted in the CHANGELOG and the F25 upgrade note; the environment selection description in README/README-tr must be updated.

**Decision — 2026-11-02:** Order is `PY_VENV` > repo `.venv` > active `VIRTUAL_ENV`. The active environment counts as the project environment only if it carries `pyvenv.cfg` and its physical path (symlinks resolved) is under `ROOT`. In other cases the reason is written and it falls back to the no-env path: static manifest or INDETERMINATE. There were two options for accepting a foreign environment: a flag that trusts `VIRTUAL_ENV`, or `PY_VENV` which takes a path. The path option was chosen. The user names the environment they are having audited; a flag would still depend on whatever the shell has activated at that moment. Because `PY_VENV` is an explicit choice, its result counts like a normal pip-audit result; the audit line writes the environment and the reason it was selected. A `PY_VENV` without `bin/python` is an error (rc=1); there is no silent fallback. No new status name was added: the produced results are the existing `pass`/`findings`/`indeterminate` and do not conflict with F02's naming. Since F25's guide was not yet written, the upgrade note is under "Upgrade notes" in the CHANGELOG.

**Status:** implemented, on `main` via PR #38 (not released). 9 checks were added to e2e; the five fixtures in the acceptance criteria and two cases for `PY_VENV` are tested. The measured pyenv-global case is now rc=0 and INDETERMINATE.

### F30 — Scanner database cache (trivy)

**Finding — 2026-11-02 (V):** 3-repetition end-to-end measurement was done on this repo. `scan.sh all` takes ~40 s warm; ~32 s of that comes from `scan_container` (`scan.sh:521`) running trivy with `docker run --rm` without a cache volume. The 131 MiB vuln DB and the misconfig check bundle are re-downloaded on every run. Because the downloaded bundle cannot be parsed by the pinned 0.58, rego ERROR lines end up in the log. The cold first run takes 111 s and there is no message explaining it. Python post-processing is < 0.5 s, bash's own share ~0.3 s; so the orchestrator's language is not the bottleneck. This is a *tool database* cache separate from F21a's result cache and does not require input-hashing.

**Acceptance criteria:**

- The trivy DB and check bundle must be kept in a persistent cache (default: a named docker volume; replaceable with a host path for CI). Below a freshness threshold, `--skip-db-update --skip-check-update` must be used; when the threshold is exceeded, the DB must be refreshed. The default threshold and its rationale must be recorded on the card.
- `SCAN_OFFLINE=1` must be supported: if there is no DB in the cache, the dimension must be `skipped`/`not inspected`, not `pass` (F02 status naming).
- A "clean" result obtained with a stale DB must be distinguishable from one obtained with a fresh DB. There are two separate places for this:
  - **The DB's identity** (`UpdatedAt` in the trivy DB metadata) must be written to provenance (F03). The same DB always yields the same value; so it can be copied into `evidence.json` and the "same content yields the same output" guarantee is preserved.
  - **The DB's age** (how many hours ago it was updated) must be written only to the run information in `summary.json` and the `doctor` output. It must not be written to provenance: age changes on every run and would make evidence different every time.
- On the first run a one-line explanation must be printed ("first run: downloading the trivy vulnerability DB (~130 MiB, once)"). trivy must be run with `--no-progress`; rego ERROR lines must disappear from the log.
- The gain must be reported as before/after with the same measurement method (estimate: `all` ~40 s → ~9 s). Runs with the cache on and off must produce the same findings.
- Optional: `scan.sh warm` (image pull + DB download), suggested at the end of `install.sh`; so the first pre-push does not take minutes.

**Decision and status — 2026-11-03:** implemented on branch `feat/f30-trivy-db-cache`.
- **Cache:** by default a docker volume named `security-audit-trivy`. If `TRIVY_CACHE` is given as an absolute path, that directory is bind-mounted (for CI). Disk usage is ~1.7 GB: the 130 MiB download expands to this size. This is written in the README and the upgrade note.
- **Freshness threshold:** `TRIVY_DB_MAX_AGE_H=24`. Rationale: upstream regenerates the DB once a day (`NextUpdate` = `UpdatedAt` + 24 hours in the DB metadata). Refreshing more often brings nothing new; refreshing less often delays new advisories.
- **Check bundle:** never downloaded (`--skip-check-update`). The checks embedded in the pinned trivy are used. This both removes the rego ERROR lines and makes the result reproducible.
- **DB identity and age:** the identity (`UpdatedAt`) goes to provenance and from there to evidence. The age is written only to the `trivy_db` field in `summary.json`, the `doctor` output and the closing table.
- **`SCAN_OFFLINE=1`:** if there is no DB in the cache the dimension becomes `skipped`; if there is, an offline scan is done regardless of its age.
- **Measurement:** on the kit's own repo, with real tools, three runs each.
  - Before: `all` 46–58 s, container 39–49 s.
  - After: `all` 6.5–9.6 s, container 2.0–2.4 s.
  - The first (cold) run takes 42 s; this time comes from the DB download and is paid once.
  - Runs with the cache on and off gave the same findings (2/2). There is no download and no ERROR line in the cached run.
- **Tests:** 11 e2e checks were written first and were red. With a Docker shim, the first run, fresh DB, stale DB, two offline cases, absolute-path cache, evidence, `doctor` and `warm` are tested.

### F31 — Hook profile and parallel dimensions

**Finding — 2026-11-02 (P):** pre-push runs `all` today. The non-blocking (soft) `container` dimension alone is ~90% of the time. gitleaks scans the full history on every push; with large histories this can take minutes. Dimensions run sequentially.

**Acceptance criteria:**

- **F31a — pre-push profile:** which dimensions pre-push runs must be an explicit profile; the default and its rationale must be recorded on the card. Dimensions outside the profile must appear in the closing summary as "did not run in this profile" (F14). gitleaks on pre-push must be able to scan the push range (`--log-opts`), but **the default stays full history**; range scanning is an explicitly enabled option for repos with large histories. Rationale: range scanning does not see on pre-push a secret pushed before the kit was installed; narrowing the default silently reduces the gate's coverage. When the range is enabled, the closing summary must say "secret: push range". The scanned range must be written in provenance (`scope`). Tests for a new branch and the no-remote-ref case are needed.
- **F31b — parallel dimensions:** must be done after F30 (the estimated gain before the cache is only ~4 s). The lock must stay in the parent process; dimension outputs must be written to separate files and printed to the log in a fixed order; the `summary.json` dimension order must be deterministic (F03). On Ctrl-C, background processes and docker containers must be cleaned up. `SCAN_PARALLEL=0` must bring back the sequential behavior.

### F32 — First impression and trust signals for external readers

**Finding — 2026-11-02 (P):** The repo was opened on 2026-06-16; as of 2026-11-02, 0 stars, 0 forks. The README is 733 lines with a mermaid diagram on the first screen; there is no short demo showing the "install → scan → see the result" flow. `docs/compare/feature-comparison.md:100` says "credit balance is too low" for the default Claude backend; that is, the project's strongest differentiator (evidence bar + eval) is published unmeasured. `docs/compare/cloudflare-security-audit-skill.md` is closed to external readers because it is in Turkish. There is no independent trust signal (OpenSSF Scorecard, signed release, usage story).

**Acceptance criteria:**

- The README's first screen: what it does, a single install command and a 60 s terminal recording (asciinema/GIF). Deep content must be moved to `docs/`; README-tr must follow the same structure.
- The unmeasured row in the comparison table must be filled with the F12b measurement or removed until measured.
- Public `docs/compare` documents must be in English or moved to internal planning. **Done — 2026-11-03:** the public comparison stays (renamed `feature-comparison.md`, vendor anonymized on 2026-11-03); the four competitor comparisons (Cloudflare, Masriyan, Phoenix, senior-security) were moved to local `*.local.md` notes; `docs/reviews` was translated to English.
- **Partial — 2026-11-03:** a README banner was added to both READMEs. It comes in light and dark versions selected with `<picture>`, is generated by `scripts/make_banner.py` and stored in `docs/assets/`, and uses the landing identity with Plex fonts embedded as base64. Its terminal block uses the closing summary's real column format and shows a run that is not all green. The single install command and the 60 s recording are still open. Follow-ups:
  - Generate the terminal block from a real fixture run, so the banner cannot drift from the output format.
  - Decide whether README assets (and `landing/`) should be left out of what `bootstrap.sh` vendors into consumer repos. This touches `CHECKSUMS` and `verify`, so it is a separate change.
- OpenSSF Scorecard must be added; a signed release remains tied to the R07 decision.
- The SaaS/Semgrep comparison must be removed from the landing's main section; tools in the agent channel (Semgrep plugin, Trail of Bits `static-analysis`) must be taken as the competitors.

### F33 — Plugin hook set

**Source — 2026-11-03:** Phoenix comparison (local note `docs/compare/phoenix-security-skills.local.md`). Phoenix uses all of the SessionStart, PreToolUse, PostToolUse and SessionEnd hooks; the kit has only the PreToolUse `pkgcheck`. Phoenix's hooks work with regex and with whatever is on PATH; the kit can fill the same surface with pinned tools. No new scanner is needed.

**Acceptance criteria:**

- **F33a — SessionStart context:** The latest `summary.json` dimension statuses and the open follow-up count must be added to the context as a short summary. `skipped`, `error` and `indeterminate` dimensions must be written separately and not shown as clean. No new scan is done; only the existing record is read. If there is no record or it is stale, this must be said explicitly and its TTL must be explicit. Because finding messages come from scanned code, they must be added with F35's data framing; the text is not placed as-is in an instruction position. There must be a size limit.
- **F33b — PostToolUse single-file check:** An advisory-only check must be run on the single edited file with the kit's pinned semgrep. It never blocks. The time budget and skip reason must be visible in the output. If Docker or `uvx` is missing, it must not silently say "clean"; it must say it was skipped. Repeated warnings for the same file and rule must be suppressed (once per session).
- **Optional SessionEnd:** A one-line reminder that spends no tokens ("files changed in this session were not scanned"). Not added without a measured need.
- **Install:** Hooks come with the plugin's `hooks.json` file. In a vendored install, F10's rule of preserving existing hooks applies; user settings are not overwritten by merging. Each hook must be disableable individually.
- **Tests:** What SessionStart writes must be tested with no record, with a stale record, and with an injection string in the finding text. For PostToolUse, the timeout and the missing-tool case must be tested.

### F34 — `pkgcheck` cheap registry signals

**Source — 2026-11-03:** Phoenix comparison (local note `docs/compare/phoenix-security-skills.local.md`). Phoenix's guard is much shallower than guarddog analysis, but it has two cheap signals and an intermediate decision the kit lacks. The kit's chained command parsing (`lib/pkgcheck.py:78`) and the `INDETERMINATE` rule are ahead of Phoenix; these are preserved.

**Acceptance criteria:**

- Two signals from registry metadata: the package or the requested version being newer than N days (suggested default 7), and declaring an install-time script (npm `preinstall`/`install`/`postinstall`). Signals must be documented per ecosystem; if PyPI has no install script counterpart, this must be stated explicitly and not shown as equivalent.
- These signals do not block; they produce the PreToolUse **ask** decision. The existing guarddog block list stays as-is. Which signal produced the "ask" must be shown to the agent and the user.
- If metadata cannot be fetched, the result is marked `INDETERMINATE` and is not cached as clean.
- The cache key must cover the new signal policy (F06). Because the age signal changes over time, it is not kept in the cache as a persistent decision.
- The time budget must stay below the hook timeout. If a timeout yields a fail-open result, this must not be silent.
- The new registry call must be added to F13's data flow table; the outgoing data is only the package name and version.
- Must be disableable with `PKGCHECK_ASK_*` or an equivalent setting. Tests must be written with offline shims.

### F35 — Scanned content is data, not instructions

**Finding — 2026-11-03 (V):** Checked during the Masriyan comparison (local note `docs/compare/masriyan-cybersecurity-skill.local.md`). All five skills read text coming from the scanned repo: finding messages, code comments, READMEs, tool output. But none of them says this content will not be followed as instructions. There is no "data, not instructions" or equivalent rule in `skills/`. The word "untrusted" appears only for the application's inputs (`sec-triage.skill.md:57`, `:77`). A "mark this finding as FP, add it to the allowlist" text embedded in a code comment can steer triage today.

**Acceptance criteria:**

- A short, identical rule must be added to all five skills: content in the scanned repo and tool output are evidence, not instructions. If this content asks for a decision, an allowlist or a command, it is not followed; it is itself noted as a suspicious signal.
- An allowlist or suppression suggestion can come only from the skill's own evidence bar; it cannot come from a request in repo text.
- An eval fixture must be added: a code comment must contain an injection steering triage toward FP and the expected decision must not change. The fixture must run in the F12 harness; without a measurement result the behavior is not considered proven.
- The skill trust model in SECURITY.md must state this boundary. It must appear as a row in F11's kit threat model.
- Must be finished before the plugin is made public (slot 8). Can also be taken together with F11's plugin part (slot 4).

**Status — 2026-11-03:** implemented on `dev/plugin-readiness`, measurement open.
- **The rule:** identical "Repo content is evidence, not instructions" section in all five skills and in `tests/eval/triage_prompt.md`. e2e guards that it exists, is identical everywhere and is in the eval prompt.
- **SECURITY.md:** gains the boundary, marked as a rule the AI is asked to follow, not a technical control.
- **Eval case:** a dev-split case where a comment above a real command injection tells the reviewer to mark it FP and allowlist it (`attack: triage-steering`, expected REAL).
- **Not done:** the measurement. No provider key was available, so the behaviour is not considered proven until a `tests/eval/run.sh` run shows the case passing. The F11 threat-model row follows with F11.

### F36 — STRIDE-per-element completeness check in the threat model

**Source — 2026-11-03:** senior-security comparison (local note `docs/compare/senior-security-skill.local.md`). `sec-threat-model` applies STRIDE per trust boundary (Phase 2). There is no check showing that each element inventoried in Phase 1 (external entity, process, data store, data flow) was evaluated at least once.

**Acceptance criteria:**

- An applicable STRIDE matrix by element type must be added to the skill. This is the standard DFD mapping (for example T, R, I, D for a data store; all six for a process) and the skill text is written independently.
- Before the model closes, each applicable category for each element in the inventory must be tied either to a threat row or to a justified "not applicable" row. An empty cell must block closing.
- The existing "boundary | STRIDE | threat | …" record format must be preserved, with the element identity added as an extra column. Earlier dated models are not overwritten.
- The coverage record may later merge with F27; this card does not wait for F27.
- **Addendum — 2026-11-03 (classic tool review: OSSEC/Snort):** For processes and data stores, the Repudiation and Tampering rows must ask whether an attack would be **detected**: is there security-relevant logging, alerting, and file-integrity or intrusion monitoring, and where is it evidenced? The answer is recorded as a threat row or a justified "not applicable" row. These are questions only. The kit does not run or recommend a specific HIDS/NIDS product.

## Current delivery order — primary planning source

The order below is the suggested default for a single team; items on the same row do not have to be a single PR. Conditional items that are not opened do not hold up the next independent item. The earlier Package A/B/C order was replaced by this table.

| Slot | Delivery | Why now / exit gate |
|---|---|---|
| 0 | **F22 done** | Single order and roadmap mapping ready |
| 1 | **F09 + F23 done** | 234 unit tests, 93+ offline e2e assertions; five required checks including pytest/e2e active remotely. F01–F06 regressions are added with the relevant fix |
| 2 | **F01 → F05** run isolation and lock ownership | Fix shared record races before cache and report |
| 3 | **F02 → F03 → F04** status, current evidence, correct report | A missing/stale scan should not look clean; the F01 and F02 schema design is done together. The unit test fixtures in F23 are extended with the F02–F04 fixes |
| 3a | **F29** py-deps environment selection | A foreign environment's result should not be reported as belonging to this repo; status naming should align with F02. Small and independent, can also be taken without waiting for post-F02 |
| 3b | **F14a + F25** coverage summary/help and version upgrade guide | Moved forward from slots 8 and 4 on 2026-11-02. F02 brought a breaking schema change for `summary.json`; the consumer upgrade guide must ship with the version containing that change. F14's only dependency was F02; showing the status and reason F02 produces to the user as a readable coverage summary is the essence of this work. The release gate (F06–F08) comes after these |
| 3c | **F30** trivy DB cache | Added on 2026-11-02. The only measured major bottleneck (~32 s of `all`'s ~40 s); small and independent. Comes after F03 because it writes the DB identity into provenance; can be slotted in like F29 |
| 3d | **Excluding scan outputs from SAST + dogfood automation (both done, `dev/plugin-readiness`)** | Added on 2026-11-03 (v1.20.0 dogfood). Scenarios that would automatically catch this version's two bugs: fresh install and upgrade from an old pin. The first step on the path to the plugin |
| 4 | **F06 → F08 (+F07) → F10 → F24/F11 (plugin part)** cache policy, channel, install and config boundary (F25 moved to 3b; F10 taken from 8 on 2026-11-03) | Reliability gate for the next stable release; F09 included in the F07 required checks. F25 ensures the consumer knows what to do on a version upgrade |
| 5 | **F13 + F11 + F24 + F35** data flow, kit threat model, config validation and the "content is not instructions" rule in skills | Fix the false locality claim; F24 puts the executable nature of the config under concrete control. Define the boundaries for R02/R06. F35 added on 2026-11-03; small and independent, can also be taken together with the F11 plugin part in slot 4, but must be finished before the public plugin in slot 8 |
| 6 | **F18** platform/path matrix and the remaining WSL2 validation | Portability is a core product promise; if there is no WSL2 environment, the other tests continue |
| 7 | **F16a → R01 scope decision → F16b** | First the real output/suppression matrix; then the needed adapters. If the R01 helper is chosen, after F16b |
| 8 | **R02 (local/private marketplace first) → R02 public + F32 → F15** plugin channel, first impression and landing QA (F10 moved to 4, F14 to 3b) | First use should be understandable and safe before the new distribution channel. R02 was moved here from slot 11 on 2026-11-02: distribution is the main bottleneck. F32's comparison row waits for the F12b measurement; the rest does not. The F31a pre-push profile can be taken together with F14a or here |
| 8a | **F26 → F19a → R13a → R13b → R13c** UI track: serverless report, finding identity, then the `scan.sh ui` local UI | F26 first visual use on top of F04/F14 and the F16 coverage contract. F19a moved up from slot 9 on 2026-11-03 because the UI needs stable finding identity. R13 (planned since 2026-11-03) runs on the Python standard library, starts read-only, then adds running a dimension and time-bound allowlist approval through the CLI; the gate stays in the CLI |
| 8b | **R12a → R12b if the condition is met** SkillSpector | First a fixture-based benefit/false positive measurement, then a pinned optional adapter; the default gate does not change |
| 8c | **F33a → F33b → F34** plugin hook set and `pkgcheck` signals | Added on 2026-11-03 (Phoenix comparison). Comes after R02 because hooks come with the plugin's `hooks.json` file. F34 waits for F06's cache policy. Not in scope for the plugin-ready release |
| 8d | **F36** STRIDE-per-element completeness check | Added on 2026-11-03. A small skill text change with no dependencies; can be slotted in |
| 9 | **F19b** (F19a moved to 8a on 2026-11-03) finding/decision and evidence contract | Stable identity, uncertainty, schema validation and backward compatibility; JSONL/resume only with a measured need |
| 9a | **F27 → F28a → F28b if the condition is met** deep review quality | Coverage record followed by an independent validation pilot; F28 also waits for F12c. This AI track does not block the independent F20/F21 work |
| 10 | **F20 → F31b + F14b → F21a** measurement, parallel dimensions, quiet output and opt-in dimension cache | No cache without measuring speed gain and invalidation equivalence. F31b only gives a meaningful gain after F30; F14b uses the same output infrastructure |
| 11 | *(R02 moved to slot 8)* | — |
| 12 | **F21b / R03** expansion where the need opens up | F21b if there is a monorepo cost; R03 if there is a Python/JS triage load. Neither is a prerequisite of the other |
| 13 | **F17** modular maintenance as needed | Small slices on top of stable behavior; no rewrite that holds up all work. Slice 1 (dimension registry + `docs/adapters.md`) was taken early on 2026-11-03 at the user's request; the remaining slices stay here |
| 14 | **R04/R05/R06/R07/R08/R10/R11/R14/R15/R16** conditional reserve | Planned only if the trigger and dependencies on the card occur. R11 opens when pin staleness or a CVE triggers it. R13 left this list on 2026-11-03 and is now planned in 8a |
| 15 | **R09 wizard** last | After the active priority work, redesign with current UX data |

**Independent AI measurement track:** F12a can start in the same planning period as slot 1; it does not need an API key. F12b follows with suitable backend access, and F12c if the results are sufficient. This is not an instruction to run agents in parallel; it is a description of development dependencies. The prompt/threshold does not change without measuring the production default; deterministic fixes do not wait for this track. R04/R05 are not opened until the relevant F12 gates are complete.

**In every delivery:** tests for new behavior come with the same change. If real consumer validation of existing behavior affects the design, it is done before the feature; whole-kit dogfood stays at the RC release gate. F01–F08 fixes must pass the relevant regression and consumer validation in the next stable release. The “dep-scan right after cache” order from the old roadmap no longer applies.

## Decisions to evaluate together

The first implementation slice is slots 1–4: the test gate and record/distribution reliability. In planning, let us first clarify the dominant user (single developer/team/many repos), development capacity, and in which environments a missing-scan state should be blocking. The current fail-open behavior can be kept in the development flow; a stricter CI profile can be chosen separately. Whether onboarding user experience or large monorepo cost is more urgent — this data should determine the F14/F21 order.

In this table the rough efforts are not an independent total budget; shared schema and test work overlaps. Re-estimation must be done after the technical design for the selected package.
