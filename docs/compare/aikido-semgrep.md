# How security-audit-kit compares — Aikido vs Semgrep vs security-audit-kit

> **Last updated:** 2026-07-10 · kit **v1.11.2**
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
| Secrets detection | ✓ | ✓ | ✓ gitleaks — full history + sub-second staged mode |
| Dependency CVE scanning (SCA) | ✓ | ✓ | ✓ pip-audit + npm/pnpm/yarn audit + OSV-Scanner (multi-ecosystem) |
| Reachability analysis for SCA | ✓ | ✗ | 🔜 planned as an optional heavy dimension (prioritizes OSV output) |
| Malicious package / typosquat detection | ✓ | ✗ | ✓ GuardDog (PyPI + npm) |
| SBOM generation | ✓ | ✓ | ✓ syft — CycloneDX + SPDX |
| License scanning | ✓ | ✓ | ✓ trivy license scanner |
| License policy gating (block on violation) | ✓ | ✗ | ✗ under consideration |
| IaC misconfiguration | ✓ | ✗ | ✓ checkov (Terraform) |
| Container / filesystem scanning | ✓ | ✗ | ✓ trivy (vuln, secret, misconfig, license) |
| CI/CD pipeline security (GitHub Actions) | Partial | ✗ | ✓ zizmor — template injection, poisoned pipelines, token over-permission |
| False-positive triage | ✓ AutoTriage (opaque) | ✗ (registry noted as noisy) | ✓ `sec-triage`: two-pass exploitability + confidence gate (≥ 0.7) + CISA KEV/EPSS check; 🔜 hard evidence bar (REAL must cite sink `file:line` + untrusted entry) |
| Measured triage quality (precision/recall evals) | ✗ (marketing claims only) | ✗ | ✓ promptfoo eval harness with recall regression gates (`tests/eval/`) |
| Structured evidence per finding | ✓ (dashboard) | Partial | 🔜 planned: `evidence.json` + JSONL artifact chain, SARIF-mergeable |
| AutoFix | ✓ AI AutoFix PRs (all plans) | Experimental | Partial — AI-assisted fixes via triage (show diff, re-scan); 🔜 validated per-ecosystem fix commands + parent-aware transitive remediation |
| PoC / exploit validation | ✓ agentic pentesting (executes) | ✗ | 🔜 planned: **generate-only** PoC mode — the kit never executes exploits |
| AI/LLM app security review (OWASP LLM Top 10) | ✗ | Partial | ✓ `sec-ai-review` skill |
| Threat modeling | ✗ | ✗ | ✓ `sec-threat-model` (STRIDE + data flows) |
| DAST | ✓ | ✗ | — rejected by design (no autonomous exploit execution) |
| Cloud security posture (CSPM) | ✓ | ✗ | — out of scope (repo-local kit; no cloud credentials) |
| Runtime protection (in-app firewall) | ✓ "Zen" | ✗ | — out of scope (scan kit, not a runtime agent) |
| Compliance dashboards (SOC 2 / ISO) | ✓ | ✗ | — out of scope; SARIF + `summary.json` are the machine-readable surface |
| IDE integration | ✓ plugin | ✓ plugin | Partial — SARIF output (`SARIF=1`) consumable by IDE SARIF viewers |
| Local / air-gapped operation | Limited (SaaS core) | Limited (no Windows local) | ✓ fully local; network only in opt-in dimensions (e.g. GuardDog) |
| Platform support | Any (SaaS); local scanner limited | Linux/macOS local (no Windows) | Linux + macOS native; 🔜 Windows via WSL2 (documented + verified path; Git Bash partial) |
| Supply-chain hygiene of the tool itself | Unpublished | Unpublished | ✓ digest-pinned tools, `CHECKSUMS` integrity manifest, SHA-pinned bootstrap with tag-repoint guard |
| Pricing | Freemium SaaS | Freemium | MIT, free |

## Why some rows are "—" (out of scope by design)

The kit's hard boundary is **scan + judge, never exploit or run in production**:

- **DAST / autonomous pentesting** executes attacks against a running target — explicitly rejected.
  The planned PoC mode is generate-only: it writes a proof-of-concept for a human to review, never runs it.
- **CSPM** requires cloud credentials and an inventory service; a repo-vendored kit has neither.
  Use a dedicated tool (e.g. Prowler) alongside the kit.
- **Runtime protection** is an agent living inside your production process — a different product category.
- **Compliance dashboards** are a SaaS surface. The kit emits SARIF and `summary.json`; whatever
  consumes them can build the dashboard.

## Measured triage quality — `sec-triage` eval harness

The kit publishes a **measured** triage quality number, and the harness that produced it, in-repo.
The eval harness (`tests/eval/`) grades the `sec-triage` REAL/FP judgment against a 61-case labeled
corpus via promptfoo, then reports a confusion matrix + precision / recall / F1 / accuracy for the
REAL class. Aikido's AutoTriage and Semgrep's registry noise claims are marketing-only — no
published precision/recall numbers.

The corpus is split so the headline number is not self-graded. A **31-case dev split** (`cases.yaml`)
is where the judgment prompt is tuned; a **30-case held-out split** (`cases.holdout.yaml`) is never
read while tuning and produces the reportable score. Most REAL cases have an FP *twin* — the same
vuln class differing by a single decisive property (a sanitizer, an allow-list, reachability, a safe
API variant) — so the FP classes contain cases a competent model can actually get wrong.

| Backend | Split | Precision | Recall | F1 | Accuracy | Confusion |
|---|---|---|---|---|---|---|
| Anthropic Claude (default) | — | unpublished | unpublished | unpublished | unpublished | not yet measured — key authenticates but every inference call returns `credit balance is too low` (400) |
| GLM-5.2 via NVIDIA NIM | dev (tuning) | 100% | 100% | 100% | 100% | TP=15 FP=0 FN=0 TN=16 |
| GLM-5.2 via NVIDIA NIM | **held-out** | **83.3%** | **100%** | **90.9%** | **90%** | **TP=15 FP=3 FN=0 TN=12** |

> **NIM run (2026-07-10):** `z-ai/glm-5.2` on `integrate.api.nvidia.com`, both splits, 0 errors.
> The default backend is still the shipped one (Claude); it stays unmeasured until the account has
> API credit.
>
> **Read the held-out row, not the dev row.** The dev split is the surface the prompt was tuned
> against, so its 100% is a training score, not a measurement — quoting it would be self-grading.
> The held-out split, unseen during tuning, is the honest number: **precision 83.3%** (the model
> over-flags), recall held at 100% (it missed no real issue).
>
> **What the corpus now resolves.** All three held-out misses are `difficulty: hard` FP *twins* —
> safe code that pattern-matches to a vulnerability: an argv-list `subprocess` call with no shell
> (`app/backup.py:30`), a `pull_request` (not `_target`) CI workflow (`.github/workflows/ci.yml:3`),
> and a zip extraction that validates member paths (`app/unpack.py:24`). GLM-5.2 got every REAL
> counterpart right but called these safe twins REAL. This is the resolving power the old 10-case
> corpus lacked (it scored a saturated 10/10): the harness can now *see* a precision failure, which
> is the precondition for measuring whether a prompt change (Phase A) actually reduces false
> positives without dropping recall.
>
> **Still not a backend ranking.** 15 REAL in the held-out split ⇒ one flip moves recall 6.7pp;
> these numbers are directional, not a basis for "model X beats Y" in a compare doc.

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
