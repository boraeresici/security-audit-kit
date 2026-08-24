# How security-audit-kit compares — Aikido vs Semgrep vs security-audit-kit

> **Last updated:** 2026-08-24 · kit **v1.16.1**
>
> Aikido and Semgrep data is taken from [Aikido's own comparison page](https://www.aikido.dev/comparison/semgrep)
> (a vendor-published source, retrieved 2026-07) plus public product docs. Aikido and Semgrep are
> trademarks of their respective owners. This table is maintained as features ship — rows marked
> **🔜 Planned** describe intended work, not commitments, and may change.

## Positioning

These are three different product shapes, so some "missing" cells are deliberate scope decisions:

- **Aikido** — an all-in-one **SaaS platform**: your code and findings live in their cloud, and the
  platform layer (dashboards, PR bots, runtime protection) is the product.
- **Semgrep** — a **SAST-first platform** (engine + registry + cloud), strongest at static code
  analysis, thinner elsewhere.
- **security-audit-kit** — a **portable local kit** vendored into your repo: a deterministic,
  pinned-toolchain scan layer plus an AI judgment layer (Claude Code skills). Nothing leaves your
  machine unless you opt in; there is no server side.

## Legend

| Mark | Meaning |
|---|---|
| ✓ | Available |
| Partial | Available with limits (noted in the cell) |
| ✗ | Not available |
| 🔜 | Planned for the kit — not shipped yet |
| — | Out of scope for the kit **by design** (see below) |

## Feature comparison

| Capability | Aikido | Semgrep | security-audit-kit |
|---|---|---|---|
| SAST | ✓ (Opengrep engine) | ✓ | ✓ semgrep (pinned), stack-aware ruleset auto-selection |
| Deep semantic SAST (authz/IDOR, business logic) | Partial (taint) | Partial (taint, Pro) | ✓ `sec-sast-deep` skill — flaw classes rule engines can't express |
| Custom rules (your own invariants) | Partial | ✓ (its core strength) | ✓ `semgrep-rules/` **composed with** the registry packs — adding a rule never costs you OWASP/stack packs — plus `doctor` showing how many rules actually **gate** (a non-ERROR rule loads and is then ignored) and `scan.sh rules-test` running semgrep's native rule tests |
| Secrets detection | ✓ | ✓ | ✓ gitleaks — full history + sub-second staged mode |
| Dependency CVE scanning (SCA) | ✓ | ✓ | ✓ pip-audit + npm/pnpm/yarn audit + OSV-Scanner (multi-ecosystem) |
| Reachability analysis for SCA | ✓ | ✗ | Partial — opt-in `OSV_CALL_ANALYSIS=go` marks whether the vulnerable symbol is actually called, paired with `--all-vulns` so the gate never loosens; `sec-triage` treats it as evidence, not a verdict. Python/JS reachability needs a heavier tool and is not shipped. Rust is refused by default: it runs the dependency tree's build scripts |
| Malicious package / typosquat detection | ✓ | ✗ | ✓ GuardDog (PyPI + npm) |
| SBOM generation | ✓ | ✓ | ✓ syft — CycloneDX + SPDX |
| License scanning | ✓ | ✓ | ✓ trivy license scanner |
| License policy gating (block on violation) | ✓ | ✗ | ✗ under consideration |
| IaC misconfiguration | ✓ | ✗ | ✓ checkov (Terraform) |
| Container / filesystem scanning | ✓ | ✗ | ✓ trivy (vuln, secret, misconfig, license) |
| CI/CD pipeline security (GitHub Actions) | Partial | ✗ | ✓ zizmor — template injection, poisoned pipelines, token over-permission |
| False-positive triage | ✓ AutoTriage (opaque) | ✗ (registry noted as noisy) | ✓ `sec-triage`: hard-evidence bar (REAL must name the sink `file:line`, the untrusted source and an unbroken path; default verdict FP) + adversarial consistency pass + confidence gate (≥ 0.7) + CISA KEV/EPSS check; suppressions are audited for decay (`scan.sh allowlist`: expired deferrals, entries with no expiry, an advisory suppressed on one dependency path but not the others) |
| Measured triage quality (precision/recall evals) | ✗ (marketing claims only) | ✗ | ✓ promptfoo eval harness with recall regression gates (`tests/eval/`) |
| Structured evidence per finding | ✓ (dashboard) | Partial | ✓ `evidence.json` — every finding in one shape, severity normalized across tools (source value kept verbatim), CVSS only where a tool supplied one; deterministic and diffable |
| AutoFix | ✓ AI AutoFix PRs (all plans) | Experimental | Partial — AI-assisted fixes via triage (show diff, re-scan) with a per-ecosystem command table (direct vs transitive-forcing) and the direct/transitive + parent-range questions asked before any bump; 🔜 computing the parent-range answer automatically |
| PoC / exploit validation | ✓ agentic pentesting (executes) | ✗ | 🔜 planned: **generate-only** PoC mode — the kit never executes exploits |
| AI/LLM app security review (OWASP LLM Top 10) | ✗ | Partial | ✓ `sec-ai-review` skill |
| Threat modeling | ✗ | ✗ | ✓ `sec-threat-model` (STRIDE + data flows) |
| DAST | ✓ | ✗ | — rejected by design (no autonomous exploit execution) |
| Cloud security posture (CSPM) | ✓ | ✗ | — out of scope (repo-local kit; no cloud credentials) |
| Runtime protection (in-app firewall) | ✓ "Zen" | ✗ | — out of scope (scan kit, not a runtime agent) |
| Compliance dashboards (SOC 2 / ISO) | ✓ | ✗ | — out of scope as a SaaS surface; the kit emits SARIF + `evidence.json` + a printable single-file HTML report you can attach to an audit |
| IDE integration | ✓ plugin | ✓ plugin | Partial — SARIF output (`SARIF=1`) consumable by IDE SARIF viewers, including the judgment findings (`kit.sarif`) |
| Local / air-gapped operation | Limited (SaaS core) | Limited (no Windows local) | ✓ fully local; network only in opt-in dimensions (e.g. GuardDog) |
| Platform support | Any (SaaS); local scanner limited | Linux/macOS local (no Windows) | Linux + macOS native; Windows via **WSL2** — documented path + `doctor` platform detection, not yet verified by us on a real WSL2 machine; Git Bash partial (docker mounts mangle) |
| Supply-chain hygiene of the tool itself | Unpublished | Unpublished | ✓ digest-pinned tools, `CHECKSUMS` integrity manifest enforced by the pre-push hook (an edited vendored copy blocks the push), SHA-pinned bootstrap with tag-repoint guard, and a pin bound to the content — `verify` fails if `.kit-version` claims a release the vendored files aren't |
| Pricing | Freemium SaaS | Freemium | MIT, free |

## Why some rows are "—" (out of scope by design)

The kit's hard boundary is **scan + judge, never exploit or run in production**:

- **DAST / autonomous pentesting** executes attacks against a running target — explicitly rejected.
  The planned PoC mode is generate-only: it writes a proof-of-concept for a human to review, never runs it.
- **CSPM** requires cloud credentials and an inventory service; a repo-vendored kit has neither.
  Use a dedicated tool (e.g. Prowler) alongside the kit.
- **Runtime protection** is an agent living inside your production process — a different product category.
- **Compliance dashboards** are a SaaS surface. The kit emits SARIF, `evidence.json` and a printable HTML report; whatever
  consumes them can build the dashboard.

## Measured triage quality — `sec-triage` eval harness

The kit publishes a **measured** triage quality number, and the harness that produced it, in-repo.
The eval harness (`tests/eval/`) grades the `sec-triage` REAL/FP judgment against a 61-case labeled
corpus via promptfoo, then reports a confusion matrix + precision / recall / F1 / accuracy for the
REAL class. Aikido's AutoTriage and Semgrep's registry noise claims are marketing-only — no
published precision/recall numbers.

The corpus is split so the headline number is not self-graded. A **dev split** (`cases.yaml`) is
where the judgment prompt is tuned; a **held-out split** (`cases.holdout.yaml`) is never read while
tuning and produces the reportable score. Most REAL cases have an FP *twin* — the same vuln class
differing by a single decisive property (a sanitizer, an allow-list, reachability, a safe API
variant) — so the FP classes contain cases a competent model can actually get wrong.

The judgment prompt (`triage_prompt.md`) mirrors the `sec-triage` skill and carries a **hard-evidence
bar**: to call a finding REAL the model must name the sink (`file:line`), the untrusted source, and
an unbroken path with no effective mitigation; a credited mitigation (parameterization, argv-no-shell,
sanitizer, allow-list, path/scheme validation, authz guard, non-privileged trigger) forces FP. The
default verdict is FP — a pattern match is not evidence of exploitability.

| Backend | Split | Precision | Recall | F1 | Accuracy | Confusion |
|---|---|---|---|---|---|---|
| Anthropic Claude (default) | — | unpublished | unpublished | unpublished | unpublished | not yet measured — key authenticates but every inference call returns `credit balance is too low` (400) |
| GLM-5.2 via NVIDIA NIM | dev (tuning, 31) | 100% | 100% | 100% | 100% | TP=15 FP=0 FN=0 TN=16 |
| GLM-5.2 via NVIDIA NIM | **held-out (36)** | **100%** | **100%** | **100%** | **100%** | **TP=18 FP=0 FN=0 TN=18** |

> **NIM run (2026-07-10):** `z-ai/glm-5.2` on `integrate.api.nvidia.com`, both splits, 0 errors.
> The default backend is still the shipped one (Claude); it stays unmeasured until the account has
> API credit.
>
> **The held-out 100% is a Phase-A *before/after* result, read it as one.** Before the hard-evidence
> bar, the same held-out cases scored **precision 83.3%** (3 false positives, recall already 100%):
> GLM-5.2 over-flagged three `difficulty: hard` FP twins — an argv-list `subprocess` with no shell,
> a `pull_request` (not `_target`) CI workflow, a zip extraction that validates member paths. The
> evidence bar took those to **0 false positives with recall held at 100%** (no real finding dropped).
> That is the measurement Phase A is judged on: FP rate down, recall not regressed.
>
> **Confirmatory vs. blind.** Those three fixed cases were seen while debugging the harness and the
> prompt's mitigation list names their patterns, so on *them* the 100% is confirmatory, not blind.
> To test whether the principle *generalizes*, six fresh held-out cases were added **after the prompt
> was frozen**, in three vuln classes the prompt never names (LDAP, CRLF/response-splitting, XPath) —
> each a REAL/FP twin (unescaped vs escaped, raw vs CR/LF-stripped, concatenated vs variable-bound).
> GLM-5.2 got all six right on the first blind run. The source→sink+mitigation principle transfers to
> classes it was not written against.
>
> **Caveats.** The corpus is now saturated for GLM-5.2 again (100% ⇒ no resolving power left; the next
> prompt iteration needs harder cases). It is one strong frontier model, not the shipped Claude
> backend, and 18 REAL per split ⇒ one flip moves recall ~5.5pp — directional, not a backend ranking.

Run a backend yourself (same corpus, same prompt, same grader — only the provider differs, so
results are directly comparable):

```sh
# NVIDIA NIM (GLM-5.2) — needs NVIDIA_API_KEY (build.nvidia.com API catalog).
# EVAL_SPLIT defaults to the dev split; the reportable number is the held-out split.
EVAL_CONFIG=promptfooconfig.nim.yaml EVAL_SPLIT=holdout bash tests/eval/run.sh
# free-tier endpoints rate-limit at the default concurrency 4 — drop it if you see provider errors:
EVAL_CONFIG=promptfooconfig.nim.yaml EVAL_SPLIT=holdout EVAL_CONCURRENCY=2 bash tests/eval/run.sh
# regression gates (exit 1 if unmet):
EVAL_CONFIG=promptfooconfig.nim.yaml EVAL_SPLIT=holdout \
  EVAL_MIN_RECALL=1.0 EVAL_MIN_PRECISION=0.8 bash tests/eval/run.sh
```

## Maintaining this table

When a kit release ships or drops a capability, update the affected rows and the version/date in the
header. Rows marked 🔜 move to ✓ with a short note of the shipping version; if a planned item is
dropped, mark it ✗ with a one-line reason.
