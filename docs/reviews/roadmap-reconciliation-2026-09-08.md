# Roadmap review and unified work order

Date: 2026-09-08 · Baseline: local `main / 48fad91`.

The current implementation order and acceptance criteria are in the [unified work list](application-backlog-2026-09-08.md). This document explains why old roadmap items were closed, merged or deferred. Sources reviewed: `ROADMAP.local.md`, `IMPLEMENTATION-PLAN.local.md`, `AI-JUDGMENT-DESIGN.local.md`, `WIZARD-DESIGN.local.md`, CHANGELOG and the related application code. Historical statements in local sources were not counted as current product/provider measurements; external tool licenses and capabilities were not re-researched.

## 2026-11-03 — three competitor comparisons and four new cards

Three Claude Code security skill/plugin repos were compared against the code at pinned commits. None was installed or run. Repos compared: Masriyan (local note `docs/compare/masriyan-cybersecurity-skill.local.md`) (`3aa77d8`), Phoenix (local note `docs/compare/phoenix-security-skills.local.md`) (`40ace4a`) and senior-security (local note `docs/compare/senior-security-skill.local.md`) (`7f92eda`). A verified SHA note was added to the Cloudflare document (local note `docs/compare/cloudflare-security-audit-skill.local.md`): `c1c8a8c`, no commits after 2026-09-14, the 2026-10-11 mapping is valid.

**Result:**
- No tool gets ahead of the kit in in-repo code security. In all three, deterministic scanning is replaced by regex scripts or an LLM prompt.
- One bug was verified in each:
  - Phoenix's injection regex always returns 0 results.
  - Masriyan's prompt-injection test gives a guaranteed false positive.
  - senior-security does not scan `.env` files.
- The divergence comes from the kit's "pinned tools scan, Claude judges" boundary.
- Where the kit lags behind is distribution: all three are on a plugin marketplace. Phoenix's hook surface is also wider than the kit's.

**Plan changes:**
- **New cards:**
  - **F33** plugin hook set (SessionStart context, PostToolUse single-file check), order 8c.
  - **F34** cheap `pkgcheck` registry signals and an "ask" verdict, order 8c.
  - **F35** "scanned content is not instructions" rule in the skills, P1, order 5. A verified gap: there is no such rule in `skills/`.
  - **F36** STRIDE-per-element completeness check, order 8d.
- **Card additions:**
  - **F19:** an epistemic state field kept separate from the verdict (`observed`/`inferred`/`unverified`).
  - **R02:** `claude plugin validate` in CI, manifest/disk consistency, and hooks shipped via `hooks.json`.
- The agreed order to the plugin (3d → 4 → 8) did not change.

**License note:** Masriyan's license adds attribution and rights-termination conditions on top of MIT. Only ideas are taken from it, not text or code.

## 2026-11-03 — v1.20.0 released

**v1.20.0** was released on 2026-11-03 (`f7d8a23`, GitHub "Latest"). Work included: F02, F03, F04, F29, F14a, F25 and F30. Steps 3, 3a, 3b and 3c of the delivery order are thereby complete.

The release went out via the RC → dogfood → final flow. Three RCs were cut before the final; two bugs found in dogfood were fixed between RCs:
- **rc.1 dogfood:** for a user pinned to an RC, `--check` suggested "upgrading" to the older v1.19.1, i.e. a downgrade. This bug was introduced by F25 itself (#47).
- **rc.2 dogfood:** since v1.0, the sample config had been copying the `SAST_PATHS=backend frontend` line as active. In every repo without these two directories, sast crashed on every scan and blocked the push. Before F02 this looked like a "HARD finding" (#48). After the fix, a real finding in the dogfood repo (`subprocess` + `shell=True`) that had until then been hidden behind the scanner error came to light.

**rc.3 dogfood:** tried on two consumer repos and a fresh install; all clean.
- **Fresh install:** the first `all` took 7.9 s, rc=0.
- **Measurements:** trivy 46 s on the first run, then 2–4 s. When `install.sh` was re-run, it listed the 4 newly added settings by name.
- **Post-release check:** for a user pinned to v1.19.1, `--check` suggests v1.20.0 and shows the upgrade notes with the breaking change first.

**Follow-up (dogfood finding):** Scan outputs committed in old versions (`docs/security/scan-findings/raw-*.log`) are also scanned by semgrep; a timeout warning was seen. The scan output directory should be kept out of SAST scope (`.semgrepignore` or `--exclude`). A small, independent item; it can be slotted in before F06.

**Decision — 2026-11-03, the path to the plugin:** The plugin (R02) is moved forward, but not as the tool for "testing a new release on different projects". Rationale:
- The plugin only carries the skill layer; the scanner core continues to be vendored into each repo.
- v1.20.0's two dogfood bugs were in the install, upgrade and config layer; the plugin would not have caught them.

To test releases on different projects, dogfood is being automated. Work the plugin directly depends on is finished before it is opened to the public.

Agreed order:
1. Take scan outputs out of SAST scope.
2. Dogfood automation: `scripts/dogfood.sh`, plus fresh-install and upgrade-from-old-pin scenarios in e2e.
3. F06 → F08 (+F07) → F10 → F24 and the part of F11 needed for the plugin.
4. R02, first as a local/private marketplace, on the user's own projects.
5. Opening R02 to the public, and F32.

**Way of working:** After v1.20.0, every item goes into the `dev/plugin-readiness` branch as a local commit. No PR, RC or release; the plugin-ready release will go out in one go via the RC → dogfood → final flow. Rationale: release and PR frequency was high.

## 2026-11-02 — F01/F05 released; F29 and F02 implemented

Item 2 of the delivery order is done. **F01** (each run in its own directory, only the lock owner publishes the record) and **F05** (the owner's liveness is checked instead of lock age, only the holder of its own token releases the lock) were released with **v1.19.0** (`ddff75f`). The rc.1 dogfood found a `kit.sarif` rename bug and temporary paths showing in messages; both were fixed in rc.2. This release's dogfood showed that the `scan-findings/` directory, which the README calls "gitignored", was not actually ignored; the fix was released with **v1.19.1** (`295532f`). Both releases were cut from a clean clone via the RC → dogfood → final flow.

**F29** from order 3a went into `main` with PR #38; **F02** from order 3 is on the `feat/f02-status-policy` branch, awaiting merge. Neither has been released yet:
- **F29:** an active `VIRTUAL_ENV` is audited only if it is a real venv inside the repo; for an environment outside the repo, `PY_VENV` is used. The measured pyenv-global case went from a HARD block to INDETERMINATE.
- **F02:** with `summary.json` schema 2, each dimension keeps `status` (six values), `reason` and gate effect separately. Gate behavior did not change. In dogfood, the semgrep exit that used to look like a "HARD finding" turned out to actually be a configuration error (`Invalid scanning root`); it is now recorded as `error`.

**Order change:** F14 (coverage summary, help) and F25 (upgrade guide) were moved behind F03 → F04 as 3b; the release gate F06–F08 comes after them. Rationale: F02 is a breaking change for consumers, its guide should ship with the same release; F14's only dependency was F02. It was noted that the order is built by criticality (P0 = verified bug that breaks trust in the result) and dependency, which is why UX work stayed behind.

**F03** (2026-11-02, `feat/f03-artifact-provenance`): evidence only uses this run's SARIF files that are in the manifest and whose hash matches; provenance is in `summary.json` and evidence. The shared `sarif/` no longer carries previous runs' files; the question left open in F01 is thereby closed.

**F04** (2026-11-02, `fix/f04-honest-report`) completed item 3 of the delivery order.
- **Report header:** writes only what it can vouch for (`clean`, `NOT complete`, `blocked`, `unknown`). A crashed tool is shown not as a finding but as "scan error, not a finding".
- **Date:** scan time and report date are separate.
- **Explicit commands:** `scan.sh evidence`/`report` exit with 1 if they cannot produce their files.
- **Dogfood:** the header that used to say "findings present (exit 1)" now says `blocked (exit 1): sast (scan error, not a finding), py-deps (findings)`.

**F04** is in `main` with PR #42.

**F14a** (2026-11-02, `feat/f14a-closing-summary`): every scan now ends with a one-screen closing summary.
- **Summary contents:** each dimension's status, duration and reason; what to do if Docker or uvx is missing; whether the blocker is a finding or a crashed scanner. There is also a new `scan.sh help` command.
- **Dogfood finding:** the summary revealed that in `pass`/`findings` states an unrelated warning looked like a "reason"; fixed.

**F14a** is in `main` with PR #43.

**F25** (2026-11-02, `feat/f25-upgrade-notes`): an "Upgrade notes" section is now mandatory in every release's CHANGELOG. `bootstrap.sh --check` shows the notes between the pin and the latest release; when re-run, `install.sh` lists new settings by name. While testing against a real repo, a pre-existing bug surfaced: with v1.19.1 released, `--check` was suggesting the older v1.19.1-rc.1 to the user. This was also fixed. 3b is thereby complete.

**F25** is in `main` with PR #44.

**F30** (2026-11-03, `feat/f30-trivy-db-cache`): the trivy DB is now cached between runs. Measured gain: `all` went from 46–58 s to 6.5–9.6 s, container from 39–49 s to ~2 s; findings identical. The PERF review's estimate (~9 s) held. By the user's decision, F30 is included in v1.20.0.

**Next:** v1.20.0. Flow: release-prep PR (including README pins, compare, landing, CHECKSUMS), then RC, dogfood and final. Then the release gate F06–F08. Each will be opened on a separate branch from `origin/main` after the previous one is merged; PRs will not be chained. Status against decisions and acceptance criteria is in the respective cards.

## 2026-11-02 — Performance measurement and positioning (F30–F32, R02 moved forward)

Following the question "would moving to Rust make it faster?", an end-to-end measurement was done on the kit's own repo; each step was run 3 times. `scan.sh all` takes ~40 s warm; ~32 s of that comes from trivy re-downloading the 131 MiB DB on every run because there is no cache. Python post-processing < 0.5 s, bash's own share ~0.3 s. Result: a language change is not on the agenda; the bottleneck was added as **F30** (trivy DB cache) and placed at order 3c. Hook profile, gitleaks over the push range and parallel dimensions became **F31**. Closing summary, Docker warning and block message were added to F14, and per-dimension duration to F20, as acceptance criteria.

A positioning review was done the same day. The repo got 0 stars in 4.5 months; the kit is not on any plugin marketplace. In the same channel there are Semgrep's official Claude Code plugin and Trail of Bits' `static-analysis` plugin. Therefore **R02** (plugin channel) was raised from a P2 candidate to P1 and moved from order 11 to order 8, behind F10. The README first screen, a demo, the unmeasured comparison row ("credit balance is too low") and trust signals became **F32**.

This review provides data for the open question in the "Decisions to evaluate together" section (getting-started UX or monorepo cost?): the measured bottleneck and adoption barriers are on the getting-started UX side. However, it was not counted as a decision.

Four corrections were applied to the plan after the review:
- **F30:** provenance will record the DB's identity (`UpdatedAt`), not its age. Since age changes over time, it would break F03's evidence determinism; age only in `summary.json` and `doctor` output.
- **F14:** split into a/b. The per-dimension `seconds` field was moved from F20 to F14a.
- **F31a:** full history stays the default; push-range scanning is an optional setting.
- **rc=2:** probably stems from the half-done F03 working tree. Not verified; will be re-measured after F03 is merged.

**Current order:** F03 → F04 → F14a + F25 (3b) → F30 (3c) → release gate F06–F08.

## 2026-11-02 — SOC platform comparison, new-vulnerability tracking and agent access (R15 note)

Claims about a commercial AI-assisted SOC platform, made in a conversation with an AI assistant, were checked. The vendor's site only mentions MITRE ATT&CK; the Sigma/YARA/Kestrel etc. libraries the assistant listed are not on it. The assistant had taken the kit for an endpoint auditing tool; the kit is a repo/supply-chain scanner. No new core feature to adopt into the kit came out of it; the web UI decision (F26 → conditional R13) did not change. New-vulnerability notification between scans, alert/agent integration and the division of labor with Dependabot are kept in the conditional note card **R15**; the delivery order did not change.

## 2026-10-21 — py-deps environment selection (F29)

While running the full e2e on the F01 branch, 6 py-deps failures that were also seen on a clean `main` were investigated. The cause was `VIRTUAL_ENV` in the developer shell pointing to the pyenv global interpreter. Because `scan_py_deps()` treats this variable as the project environment when the repo has no `.venv`, the venv-less fixture produced a HARD block instead of INDETERMINATE. The test side (`unset VIRTUAL_ENV`) was fixed on the F01 branch. The product behavior was moved to card **F29**: P1, order 3a, consistent with F02 status naming. The possibility of a false `pass` is an inference from the code path, not measured.

## 2026-10-11 — Cloudflare feature comparison

A Cloudflare comparison (local note `docs/compare/cloudflare-security-audit-skill.local.md`) was done against local `078cf18`. Threat model, evidence chain, signal-driven deep review and JSON/SARIF/HTML already exist; no re-development was opened. The current “independent” triage instruction does not provide a separate validator context; the coverage note is also not a verified coverage ledger.

F11 was extended with execution/artifact boundaries, F12 with uncertainty semantics, F19 with a versioned verdict schema and re-verification of old verdicts. The new **F27** whole-repo coverage record and **F28** independent validation pilot are at order 9a, after F19. F28's F12c quality dependency is kept; the AI track does not block performance work. **R14** expert domain content is a conditional reserve. The decisions R05 generate-only and R09 last did not change.

In this round no code or skill prompt was changed; no new security scan/eval was run. Previous RC/CI results are not counted as re-verified. External `main` contents were read from the web; since the remote commit SHA could not be obtained, the comparison is not a pinned benchmark. Detailed evidence and sources are in the comparison file, acceptance criteria in the unified backlog.

## 2026-09-14 — SkillSpector and UI priority decision

Following the user's review, the [unified backlog](application-backlog-2026-09-08.md) was extended with three cards: **F26** serverless HTML report usability, **R12** SkillSpector pilot/adapter, **R13** conditional local scan UI. Default order: current P0/P1 reliability and coverage work → F26 → R12; R13 is opened only if report usage proves insufficient. F26/R12 were placed in the delivery order as 8a/8b, before the F19/cache expansion; they do not require an AI runner or a persistent verdict store.

The CLI execution core is kept. The current HTML report is not rewritten; search/filter/detail are added. F04 honest report and F03 run provenance are the foundation of the visual expansion. SkillSpector is a separate candidate for pre-install skill security; it does not duplicate the R08 general scanner reserve. First false-positive/miss measurement, then a pinned, reporting-only optional adapter; it is not added by default to `all`/pre-push or the automatic hard gate scope. Source and acceptance criteria are kept in the R12 card.

R13 can be opened on a real UI need even if SkillSpector is not successful; F01–F05 and the F11/F24 boundaries are prerequisites. AI review from the UI depends on R04, verdict writing on F19; they are separate items. Wizard R09 remains the last planned feature; its need is re-evaluated before solving the same onboarding problem twice with the UI.

In the RC check, 234 unit tests and 93 offline e2e assertions passed. RC.1's invalid `actions/setup-python` pins were fixed to v6 in RC.2; post-merge CI ran green and the remote required-check list was matched with the local ruleset. F09 and F23 are complete. In RC.2's real consumer dogfood, the old bootstrap's two-field pin check rejected the install because the CHANGELOG said `Unreleased`. RC.3 prepares the section header as `1.18.0`, prevents the release script from cutting a tag with a mismatched CHANGELOG, and verifies the legacy RC pin in E2E.

## Core decision

We are updating the old order's “cache immediately, then remediation and heavy reachability” flow. First, the faulty scan records and the package-cache policy problem will be fixed. A cache is valuable only once we can prove it stores the correct result. On the other hand, remediation's small scope decision and L1d's keyless preparation do not have to wait for the cache.

F21 from the initial review was also split into two deliveries: **F21a dimension cache → F21b monorepo scope**. The monorepo delivery will not wait for the cache to ship. F12 was split into **definition/measurement infrastructure → backend measurement → product verdict change**. The current historical results are not sufficient to change the 0.7 threshold.

## Existing or closed items — no re-development

| Old reference | State seen locally / evidence | New decision |
|---|---|---|
| T1.1–T1.4; C1; plan #4; Phase A | Evidence threshold, exclusion, reachability, 3-stage review and consistency check exist in `skills/` | Foundation done; calibration/UNCERTAIN gap is F12 |
| T2.1; R1/R2; plan #15 | AI surfaces, threat model, incomplete-fix and availability questions exist | No re-adding; quality measurement in F12 scope |
| T2.2 offline OSV→SQLite | The roadmap already dropped the custom DB sync; `scan_osv` exists | Closed; do not equate OSV's presence with the whole flow being network-free, F13 |
| T2.2 / #8 judgment half | `sec-triage` asks direct/transitive and parent-range questions | Exists; only the compute need is R01 |
| T2.3 KEV/EPSS | Skill and CHANGELOG describe an optional live query | Exists, but do not count the roadmap's initial “offline snapshots, pinned” design as realized; fix in F13 |
| T3.1 / plan #5 a+b+c | `lib/evidence.py`, `lib/kit_sarif.py`, `lib/report_html.py` and schema exist | All three outputs done; correctness F01–F04, coverage F16; JSONL/resume a separate remaining need |
| T3.3 / Incoming sec-audit | Orchestrator exists | Closed |
| Tier S Layer 0/2 + non-crypto + CI pins | bootstrap pin check, CHECKSUMS/verify and pinned workflows exist | Foundation done; release gaps F07/F08, threat model F11 |
| Incoming OSV; A1/A2; plan #1/#2 | `scan_osv`, `scan_guarddog`, `scan_zizmor` exist | Do not count old empty checkboxes as new work |
| L1/C3; L1b/#10; L1c | Harness, matrix config, provider filtering/score grouping exist; 31 dev + 36 holdout = 67 case headers in YAML | Infrastructure done; not a corpus/model quality claim. Calibration and new coverage F12 |
| plan #12 suppression fan-out | Skill mapping table and mandatory re-scan exist | Mechanism done; real trivy/uv.lock verification F16a; alias/verdict lifecycle F19 |
| plan #13 allowlist drift | Exists in `scan_allowlist` and CHANGELOG | Foundation done; exact-id and existing-file limitations F19 |
| plan #14 local rules | Discovery, adding local rules and `rules-test` exist | Done; do not add consumer-specific rules to the kit |
| plan #11 stack-auto field verify | The previous plan closed it with e2e since no suitable real consumer was found | Keep closed; if a suitable consumer appears, add to an RC round, not an independent blocking item |
| R5.1 install-time hook | `pkgcheck`, parser, PreToolUse hook exist | Feature done; cache policy bug F06 |
| R5.2 slice A | Lock code is on main; released in v1.19.0 with the F01/F05 fixes (2026-11-02) | Done; cache slice (slice B) in the F20 → F21a order |
| #9 WSL2 | Docs/platform detection exist; no real WSL2 verification | Partial; remaining is F18, do not open a new platform-docs project |

## Assessment of open roadmap items

| Old item | Value / cost assessment | New counterpart / opening condition |
|---|---|---|
| R5.2 slice B | Reduces repeated scan cost; missing invalidation makes a false clean result persistent | F21a after the F20 measurement; kit/pin/config/rule/allowlist/advisory freshness included in the key; dimensions that cannot be proven stay out of the cache |
| R5.4 affected subtree | Useful in a large monorepo; shared lockfiles and common components can miss scope | F21b; after F21a, if there is a real monorepo bottleneck |
| L1d calibration | High value for giving meaning to the AI layer's current quality claims | F12a keyless definition/rubric/fixture → F12b same-split measurement → F12c product change; earliest independent track |
| #8 compute half | Can give the user an actionable fix; writing a resolver for all ecosystems is expensive | R01 first a K-effort scope decision. If the skill's current read-only commands suffice, do not open new scanner code |
| #7/A3 Python-JS reachability | Go slice exists. The rest brings heavy installation and runs that can take minutes | R03; limited pilot after a consumer showing high triage load + F21a + F16 |
| R5.3 skills-only plugin | Makes trying the judgment layer easier without vendoring; dependencies on the scanner path must be resolved | R02; after F10/F11/F14. First the manifest/permission/root contract, then distribution. Phase B is not a prerequisite |
| T3.2/#6 and B.1 extraction | The roadmap's own measurement refuted the continuous token-saving rationale | R10 deferred; no standalone refactoring without a real maintenance problem or R04 need |
| T3.1 JSONL chain; Phase A SQLite/checkpoint | Reports exist, but a durable event history/resume are different capabilities | Conditional slice tied to the F19 identity/verdict model; do not build JSONL and a DB together without showing the cost of interrupted long runs |
| T3.4 prove-it PoC | Can strengthen review evidence; generation cost and security boundary are higher | R05, need-based after F12/F19; generation only, no automatic execution |
| L2 triage-lite + Phase B | Answers the offline/non-Claude need; tool loop and quality responsibility are a new maintenance burden | R04 one program, two consecutive slices: a measured triage-lite pilot; a full agent loop if needed |
| L3 deep on a strong model | Not a feature delivery but a quality constraint | R04 acceptance criterion. Historical assumptions that a small model is sufficient or a large model insufficient are not used in place of measurement |
| Python tool hash-pin | Provides extra integrity; per-tool dependency/platform locks need maintenance | R06; after F11, first a maintenance-cost decision; do not silently change the runtime model |
| Tier S Layer 3 cosign/Rekor | Answers the need for independent publisher identity | R07; after consumer/adoption demand and F07; alongside, not instead of, the current hash check |
| A4/A5 scorecard/conftest/modelscan | Necessity for the general user not shown | R08 conditional; if there is a concrete static coverage gap, compatible distribution and license verification |
| CLI wizard | Design/mock ready; new runtime value not yet measured | R09; the earlier “last” preference is kept; F14 short help is not a wizard replacing it |
| MCP inputs / declarative manifest / SQLite | Valuable if there is integration or orchestration pain | MCP requires a real data consumer for R04 or F16; manifest/resume are not opened as a separate main item without measurement |

## Not taken into the active order

Although Nuclei was a “maybe” in the early list, it was left out of scope in the later Round 4 DAST decision. It is not reopened without a new request. R3 fuzzing/differential testing, runtime monitoring, host/DB backup tools, CSPM, autonomous exploits, external agent multiplexers and tools that duplicate existing scanners are not kit work. The need is handled in the consumer project; even a sample fuzz scaffold requires a separate request.

The current ordering is not an external package selection or installation approval. When plugin/provider work is to be implemented, the relevant host contracts and the tools' features/licenses as of that day must be re-verified. What is done now is a value and dependency assessment of the existing local designs.

## Changes relative to the old order

1. The lock slice is no longer “done, move to cache”; F01/F05 correctness fixes first.
2. The F09 test gate moved to the front; F07/F08 became the gate before the next stable release.
3. The remediation scope decision R01 was moved before the heavy cache/reachability work; we do not mix the small decision with the big implementation.
4. Calibration F12a can start without depending on a key. Measurement F12b and product change F12c are separate gates; the 0.7 threshold is kept for now.
5. Plugin R02 is the expansion candidate before heavy reachability R03; not a permanent preference, but items opened by onboarding and triage data.
6. F21a cache and F21b monorepo are delivered separately. JSONL/resume was conditionally tied to F19.
7. Wizard is the last planned feature; local model, full provider runner, new scanner and signing did not become automatic sprint commitments.

## Verification and maintenance

In this round only planning documents were updated; application/prompts were not changed, tests or LLM eval were not re-run. Functions in the current code, CHANGELOG, eval provider grouping/filtering and corpus header counts were compared. The previous review's 93/0 offline test result is not presented as a new run.

Local roadmap/plan files remain gitignored; the persistent shareable source is the unified work list under `docs/reviews/` and this mapping document. As of 2026-11-03, the competitor comparisons in `docs/compare/` are local-only `*.local.md` notes; only `feature-comparison.md` is public. Remote release/issue status was not queried in this round. Old research texts are kept as history; in case of conflict, the current work order prevails.
