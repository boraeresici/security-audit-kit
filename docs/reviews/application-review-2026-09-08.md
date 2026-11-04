# Security Audit Kit — multi-role application review

Date: 2026-09-08 · Local commit reviewed: `48fad91` · Branch: `main`

This review was prepared without changing application code. All items are proposals; it does not count as approval for planning or implementation. Prioritized counterpart: [work list](application-backlog-2026-09-08.md).

## Executive assessment

The product's strong core is that it combines different security scanners into a single flow that can be carried inside the repo, and separates scanning from AI judgment. Version/digest pinning, an integrity manifest, a daily raw log, SARIF, normalized evidence and an offline HTML report exist. Before adding new scanners, **reliably showing which run the output belongs to and what was actually scanned** carries higher value.

Most important result: although the current offline e2e tests pass, lock timeout, a missing scanner and stale SARIF composition can produce a wrong scan record. These are classified not as security vulnerabilities with a demonstrated exploit in production, but as locally verified correctness and reliability bugs.

Recommended order: record reliability → automated quality gates → installation and result understandability → measurement-justified performance and coverage improvements.

## Scope and method

Surfaces reviewed: `scan.sh`, `bootstrap.sh`, `install.sh`, three hooks, the four Python modules in `lib/`, five `sec-*` instructions, the e2e/eval structure, CI and release flow, English/Turkish README, security policy, evidence schema, landing HTML/build/headers and local roadmaps.

The roles are separate review perspectives; no claim is made that independent human/agent reviews were performed.

- **V — Verified by experiment:** behavior reproduced with synthetic data in a temporary Git repo.
- **C — Code/doc evidence:** implementation path or explicit documentation limitation reviewed; impact not measured end to end.
- **P — Proposal:** product opportunity that must be validated by user/performance measurement.

No attack on a live service, external scanner download/run, paid LLM evaluation, real WSL2 test, user interview, or in-browser visual/accessibility test was performed. Competitors' current features and the current CVE status of pinned tools were not verified within the scope of this work. For the landing page, the results are a source-code review.

## Verification results

| Check | Result | Comment |
|---|---|---|
| Initial working tree | Clean | No existing user change was overwritten |
| Shell syntax | Nine selected scripts passed `bash -n` | Not a substitute for ShellCheck or behavior tests |
| Python syntax | The four modules in `lib/` passed an AST parse check | Not a substitute for runtime/adapter compatibility tests |
| `bash scan.sh verify` | 69 files matched the manifest | Integrity of the tracked files at the start |
| Offline e2e | **93 passed, 0 failed; 10 sections skipped** | `PATH=/usr/bin:/bin:/usr/sbin:/sbin bash tests/e2e.sh`; external scanners and Node were not on this PATH |
| Second scan while lock is held | Shared `summary.json` changed | F01; `SCAN_LOCK_WAIT=0`, lock with a live PID |
| Secret without Docker | Exit 0, dimension `pass` | F02; the scan was actually skipped |
| Stale SARIF + skipped secret | Previous synthetic finding was pulled into the new evidence; no warning | F03 |
| Evidence without an exit code → HTML | Printed `clean (exit 0)` | F04 |

### Reproduction recipe

In a temporary Git repo, put a single synthetic result into `docs/security/scan-findings/sarif/gitleaks.sarif` and a distinguishable marker into `summary.json`. Write `pid=<PID> date=now cmd=fixture` for a still-living process into `.git/security-audit-cache/scan.lock/owner`. From inside this repo, using the kit's absolute path, run `PATH=/usr/bin:/bin:/usr/sbin:/sbin SCAN_LOCK_WAIT=0 SARIF=1 /bin/bash <kit>/scan.sh secret`. Verify that Docker is not on this PATH.

Observed result: despite the “SEPARATE log” message, the shared summary was overwritten; the `secret` status became `pass`; evidence contained a stale finding and output `warnings=[]`. This experiment deterministically exercises the lock-timeout path; it is not a load test with two real scanners running at the same time.

For F04, JSON containing `schema=security-audit-kit/evidence@1`, `scan={}`, `counts={total:0}`, `findings=[]` was rendered with `lib/report_html.py`; the output contained `clean (exit 0)`.

## Review by role

### 1. Product manager

**Strong:** Local, repo-scoped use, low infrastructure needs, and the split between deterministic checks and judgment form a clear product identity. Having extra dimensions like OSV/GuardDog/zizmor be optional keeps cost under control.

**Improvement:** The `all` command does not cover OSV, GuardDog, zizmor and SBOM (`scan.sh:1137`). This is deliberate and documented; but it can clash with a first-time user's expectation of a “full scan”. A coverage summary showing active, not-applicable and optional dimensions before/after running, plus usage profiles, is recommended (F14).

Landing statements like “Nothing leaves your machine” / “network only in opt-in dimensions” need a data-flow explanation consistent with the standard flow being able to use `uvx`, registry rules, dependency audit and an AI service. Local execution, no-network and data being sent to an external service should be explained as separate concepts (F13). This review did not measure real network packets.

Product success should be measured not by the number of new tools but by time to the first useful report, missing-coverage rate, scan latency and the rate of closed real findings. These can start with local metrics without default telemetry (F20).

### 2. Developer experience / UX

**Strong:** `doctor`, zero configuration, bilingual README, `--skills-only`, copyable install commands and a framework-independent report are good starting points.

**Improvement:** Installation directly changes the existing `core.hooksPath` value (`install.sh:45`); although the README describes alternatives, installation does not detect the existing hook owner and show concrete options. An installation plan that preserves existing behavior, plus backup and rollback, is needed (F10).

Improving `scan.sh` command help and the result summary, and splitting the long README into getting started/advanced use/reference, reduces first-use friction (F14). Because `scan_report()` and `scan_evidence()` return 0 on missing input or some generation errors, automation has to separately check that the file was actually produced (F04).

The landing copy button has no error path for clipboard rejection; animated visibility depends on `IntersectionObserver` and JS (`landing/index.html:543`). Use with JS disabled, keyboard focus, copy failure, screen-reader announcement and mobile overflow should be tested in a browser (F15). Reduced-motion support already exists; it should not be counted as a feature to redo.

### 3. Software architect / backend

**Strong:** The Python helpers run on the stdlib; evidence as the shared model decouples the report and SARIF generators. The main behaviors are split into functions.

**F01 — V, high:** When the lock cannot be acquired, `scan.sh:1193` only changes the `LOG` path. `SUMMARY`, `SARIF_DIR`, `EVIDENCE` and the HTML path stay shared; the atomic rename around `scan.sh:1230` still changes the shared summary. Atomic file writes do not prevent different runs from claiming the same record. Each run should use a separate directory; a shared “last completed run” pointer should only be updated under a proper lock.

**F02 — V/C, high:** `scan_secret()` and missing-toolchain paths return 0 (`scan.sh:375`, `396`); summary generation turns 0 into `pass`. The existing `indeterminate` approach for a missing Python manifest should be carried to all dimensions. Scan result and blocking policy should be separate fields; missing coverage can be recorded correctly without blocking development.

**F03 — V, high:** `lib/evidence.py:392` picks files by dimension name; it does not verify whether the file was produced in this run. When the same dimension is skipped, stale SARIF counts as valid. A run ID, commit/scope information and that run's artifact manifest are needed.

**F05 — C:** `scan_lock_acquire()` can delete a lock that has exceeded the age limit even with a live PID; `scan_lock_release()` deletes the directory without verifying an ownership token (`scan.sh:1090`). Long-scan and PID-reuse scenarios should be handled with an ownership token/heartbeat and race tests.

**F17 — P:** `scan.sh` carries scanner adapters, discovery, locking, allowlist, cache and JSON generation in a single file. It is appropriate to first pin the behavior contracts with tests and then split into small modules; there is no evidence for rewriting the whole system.

### 4. Security engineer / supply chain

**Strong:** Image digests, pin verification, tag-repoint checking, the manifest, redaction and explicit handling of build-script risk are valuable. These controls should be kept.

**F06 — C, high:** The `pkgcheck_one()` cache key includes ecosystem, package, version and GuardDog version; it does not include `PKGCHECK_BLOCK_EXTRA`/`PKGCHECK_REPORT_EXTRA` (`scan.sh:551`). The previous verdict, rather than the raw analysis, is read from the cache. When the policy is tightened, the previous verdict can be reused. The raw analysis should be cached and the current policy applied, or a policy digest added to the key. An explicit refresh/invalidation rule should also be defined for the indefinite cache on exact versions.

**F07 — C, high:** Around `scripts/release.sh:60`, missing `gh`, check-runs not found and missing required checks pass with a warning; `preflight` can continue after a failed fetch. The mandatory verification in the release document and the automation's behavior diverge. For a stable release, an unverifiable check should be an explicit failure; if an emergency exception is needed, it should be separately recorded and deliberate.

**F08 — C:** `bootstrap.sh:60` picks the update candidate by sorting all version tags; `-rc.N` is not filtered out. The possibility of the stable channel suggesting an RC should be tested with a local tag fixture. Channel selection consistent with the stable/RC split in `RELEASING.md` is needed.

**F11 — C:** `.security-audit.conf` is sourced as shell (`scan.sh:48`); it is not a normal configuration data file but executable code. Scanner containers mount the repo writable. In the kit's own threat model, the repo/config/tool/output boundaries should be documented explicitly; moving to a data-format config and a read-only source/separate output mount should be evaluated with a compatibility experiment. No attack or compromised scanner was demonstrated here.

### 5. QA / release engineer

**Strong:** 93 offline assertions, synthetic stack fixtures, integrity/tamper tests and a culture of trying RCs on a real project exist.

**F09 — C, high:** `.github/workflows/ci.yml` only runs ShellCheck and checksums; self-audit runs secret/SAST. `tests/e2e.sh` is not a required PR check. Local e2e before release does not fully replace it. Offline deterministic e2e should be a PR gate; real scanner adapter smoke tests should be a separate scheduled job. Skipped tests should be counted in the report.

**F18 — C/P:** Against the Linux/macOS claim, CI is limited to Linux; the comparison text states that WSL2 has not been verified on a real device. The support matrix should be explicit with Bash/Python versions. Spaces in file paths should be tested separately: `scan.sh:421` passes changed files, and `scan.sh:1026` the findings argument, as a string that can be split on spaces. A path with spaces was not tried end to end in this work.

### 6. AI evaluation / applied research

**Strong:** The evidence threshold, counterexamples, dev/holdout split, precision/recall and separate handling of provider errors are a mature approach.

**F12 — C, high:** `skills/sec-triage.skill.md:69` recommends FP by default when evidence is missing, while the same flow also defines UNCERTAIN. `tests/eval/triage_prompt.md` and the grader use a binary REAL/FP contract. The distinction between “not insecure” and “no context to decide” can be lost; whether the false-negative rate actually rises was not measured in this review. A contract that records missing context as UNCERTAIN and does not feed it into the automatic allowlist should be measured with new dev cases; the prompt should not be changed directly.

`tests/eval/README.md` says the default Claude backend was not measured; this historical record does not count as a current test result. The corpus size description is also inconsistent between 61/30 and the later 36-holdout description. Corpus counts and the measurement report should be generated from code; prompt hash, model ID, dataset version, abstention and coverage should be reported together. Deep/AI-review passes and resistance to malicious instructions embedded in scan output need separate evaluation (F12).

### 7. Data / reporting

**Strong:** The severity source of the evidence is preserved; the Python HTML generator escapes text; the report is a single file and needs no external service.

**F04 — V/C:** Around `lib/report_html.py:191`, a missing `exit_code` is treated as clean; every non-zero code is shown as “findings present (exit 1)”. Tool error, missing coverage and a security finding should be separated. Report generation time and scan time should be kept separate; `scan.sh report` can stamp today's date onto stale evidence.

**F16 — C:** The evidence adapter list (`lib/evidence.py:21`) is limited to gitleaks, semgrep, trivy, osv and zizmor. Raw findings from the pip-audit, JS audit, checkov and GuardDog dimensions are not taken directly into the shared model. It should not be assumed that the HTML after `scan.sh all` contains all findings of all dimensions; first a coverage matrix, then the missing adapters, are needed.

**F19 — C/P:** The finding ID is dimension+rule+file+line (`lib/evidence.py:135`); a line shift changes the ID. Different packages at the same rule and manifest location can merge during dedup. Examples should be verified with package name/version/purl, tool fingerprint and commit context. The allowlist check is limited to exact-id and existing file pairs (`scan.sh:865`); automatic fan-out should not be done without alias matching/applicable-dimension information. Owner, justification, expiry date and re-verification info can be kept in a shared decision record.

### 8. Maintenance / operations

**F20 — P:** Per-dimension duration, failure reason, skip reason, file count and cache-hit information tie performance decisions to evidence. Measurement first, then cache and monorepo scope optimization (F21). Cache correctness cannot be ensured without accounting for tool/rule/config/scope/database changes.

**F22 — C:** The local plans contain bulk items for existing features such as evidence/HTML and stale “unreleased” states. `ROADMAP.local.md` shows R5.2 slice A as done and unreleased; the local HEAD proves the lock change is on main, but whether it was released was not verified remotely. Done work should not be relisted as new development. A link should be established between a single current backlog and the historical research notes.

## Product boundaries to keep

This review does not propose DAST/autonomous attack execution, a SaaS dashboard, CSPM, or increasing the number of scanners. The product identity in the current roadmap should be kept. Network-free report generation, optional heavy checks and the raw finding/judgment split should remain in the acceptance criteria of subsequent development.

## Roadmap merge update — 2026-09-08

The roadmap, implementation plan, AI design and wizard design were reviewed separately. The [mapping document](roadmap-reconciliation-2026-09-08.md) separates existing features from the real remaining work. Current order: F09 → F01/F05 → F02/F03/F04 → F06/F07/F08; then coverage, installation and measured performance work. The F12 calibration track is independent; F21 was split into two deliveries, cache and monorepo. The initial proposal below is history; the current work order is the backlog table.

## Initial planning proposal — current order is in the backlog

First, select a “reliable record” package with F01–F04 and F09. F05/F06/F07 should follow in the same reliability period. The AI verdict contract F12 should proceed with a separate measurement gate. Cache, monorepo and new distribution channels should be planned only once this foundation and the needs measurements are ready. Detailed acceptance criteria and dependencies are given in the work list.
