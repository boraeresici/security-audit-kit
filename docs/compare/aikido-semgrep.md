# How security-audit-kit compares — Aikido vs Semgrep vs security-audit-kit

> **Last updated:** 2026-07-06 · kit **v1.11.1**
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

## Maintaining this table

When a kit release ships or drops a capability, update the affected rows and the version/date in the
header. Rows marked 🔜 move to ✓ with a short note of the shipping version; if a planned item is
dropped, mark it ✗ with a one-line reason.
