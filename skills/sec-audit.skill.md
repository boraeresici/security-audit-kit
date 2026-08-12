---
name: sec-audit
description: One-command security audit orchestrator. Runs the deterministic scan, triages the findings, and (SIGNAL-GATED, not blindly) runs the deep judgment passes that actually apply to this repo, consolidating everything into one findings file. Use it when you want "just audit this" without deciding which skill to run — e.g. "audit this repo", "run a security review", before a PR / cutover.
---

# sec-audit — one-command audit orchestrator

The single entry point so you don't have to remember *which* skill to run. It drives the
deterministic scan + the judgment skills (`sec-triage`, `sec-sast-deep`, `sec-ai-review`,
`sec-threat-model`) and produces **one** consolidated `findings-<TODAY>.md`. You run it; you
read the final report.

**Hard boundary — never edit the kit itself.** `tools/security-audit-kit/` is **read-only** for
every pass this skill drives: never edit `scan.sh`, the hooks, the skills or `CHECKSUMS`, not even
to fix a genuine bug. `scan.sh verify` (run by the pre-push hook) fails for the whole team
afterwards, and the next `bootstrap.sh` discards the edit without warning. Kit bugs go in the
consolidated findings file under **Kit issues** (behaviour, expected behaviour, file:line); the fix
belongs upstream, in a release, behind a bumped pin.

**Cost discipline (important):** the deep passes are token-costly and are NOT run every time.
Default = scan + triage only. A deep pass runs **only** when a clear signal in the repo calls
for it (below), or when you explicitly ask (`deep` / "run everything"). Always announce which
deep passes you will run and **why** before running them.

**Two modes — pick by the ask, announce which you're in:**
- **Routine (default)** — scan + triage, plus the signal-gated deep passes (Steps 1–5 below). This
  is "audit this repo" / a pre-PR pass.
- **Whole-repo blueprint (opt-in, deepest, most tokens)** — the 3-stage
  threat-model → per-component vuln classes → strict-evidence audit (see *Whole-repo blueprint*
  below). Use it only for "deep/thorough audit the whole repo", a pre-cutover review, or an
  explicit request — never as the routine default. It still honors the same evidence bar and the
  signal-gating spirit (audit the components that matter, not every file).

## When
- "Audit this repo", "run a security review / security pass", "just check this".
- Before a PR / cutover when you want the right things run without picking them yourself.
- NOT a replacement for the cadence — it *applies* the cadence for you (routine scan+triage
  always; deep passes on signal/request).

## Steps

1. **Deterministic scan.** Run `bash tools/security-audit-kit/scan.sh all` (or `fast` for a
   quick pass). This writes the raw log + `summary.json`.

2. **Triage (always).** Apply the `sec-triage` method: read `.security-exclusions.md` →
   Pass 1 (exclusions + reachability filter) → Pass 2 (confidence ≥ 0.7) → write
   `docs/security/scan-findings/findings-<TODAY>.md` (with the Suppressed section). For a
   dependency CVE you're about to defer, do the KEV/EPSS check (per `sec-triage`).

3. **Detect signals → choose deep passes.** Inspect the repo and decide which deep passes
   *apply*. State each decision (run / skip) with the signal:
   - **`sec-sast-deep`** if there are **authorization surfaces** or they changed — routes/
     endpoints/resolvers, role/permission checks, multi-tenant scoping, four-eyes/approval
     flows. Signal: `git grep -nE '@router\.|@app\.(get|post)|permission|has_perm|tenant|@PreAuthorize'`
     or changed endpoints in the diff. **Also** when there are **raw injection sinks** semgrep
     may miss across the call path — Signal: `git grep -nE '\.raw\(|\.extra\(|RawSQL|render_template_string|child_process|\bexec\(|pickle\.loads|yaml\.load\b'`
     (its Class 4 covers semantic/stack-specific injection).
   - **`sec-ai-review`** if the code **calls an LLM / exposes tools or agents / does RAG**.
     Signal: `git grep -nE 'anthropic|openai|chat\.completions|invoke_model|generate_content|tools=|tool_call|mcp'`.
     Skip entirely if no LLM.
   - **`sec-threat-model`** if there is a **new subsystem / trust boundary** or the user asked
     for a design/threat review. Not on a routine pass.
   - **`deep` / "run everything" requested** → run all applicable; still skip ones with no basis
     (e.g. ai-review with no LLM).

4. **Run the chosen deep passes** (each per its own skill), **appending** their findings to the
   SAME `findings-<TODAY>.md` (do NOT overwrite) — so everything lands in one report.

5. **Consolidate + report.** One findings file; a final summary: what scan ran, which deep
   passes ran and **why** (or were skipped), counts (REAL / UNCERTAIN / FP / suppressed),
   applied fixes/allowlists, opened follow-ups. Point the user at the findings file.

## Whole-repo blueprint (opt-in deep mode — 3 stages)
A structured whole-repo audit for when scan+triage isn't enough (pre-cutover, "thoroughly audit
this", a security review of the entire surface). It is the most token-costly path — announce it,
scope it, and let the user narrow it. Credit: seclab-taskflow-agent's threat-model→plan→audit shape.

**Stage 1 — threat-model the repo (breadth, cheap).** Before auditing anything, map the surface so
the audit is targeted, not a file-by-file crawl:
- **Components & trust boundaries:** entry points (HTTP/GraphQL routes, CLI, queue consumers,
  webhooks, cron), the data stores, external calls, and where untrusted input crosses into trusted
  code. `git grep -nE '@router\.|@app\.(get|post|put|delete)|path\(|def handler|@task|consume|webhook'`
  + read the top-level layout; don't paste whole trees — slice.
- **Assets & what an attacker wants:** credentials/secrets, PII, money/ledger, tenant isolation,
  admin capability, RCE. Note which components touch each asset.
- Output: a short component → (boundary, assets, entry points) map. This is the audit plan's spine.

**Stage 2 — per component, name the vuln classes worth auditing (targeted, not generic).** For each
component from Stage 1, pick the classes that actually apply to *what it does* — do not run a generic
checklist everywhere:
- an **auth/session** component → broken-auth, missing/again-vertical authz, weak crypto, JWT/verify;
- a **data API** → injection (defer single-sink patterns to semgrep; hunt the call-path/stack-idiom
  ones per `sec-sast-deep` Class 4), IDOR/horizontal authz, mass assignment;
- a **file/upload/report** path → path traversal / zip-slip, SSRF, deserialization, XXE;
- an **LLM/agent** surface → hand to `sec-ai-review` (prompt injection, insecure output handling);
- **IaC / CI** → route to the `iac` / `zizmor` dimensions + the misconfig classes.
- Output: a per-component audit list `(component → classes)`. State what you are NOT auditing and why.

**Stage 3 — audit each component against its classes, at the hard-evidence bar.** For each
`(component, class)`, follow the call path and apply the SAME bar as `sec-triage`/`sec-sast-deep`:
default FP; REAL only with a named **sink `file:line`** + **untrusted source** + **unbroken path**
(a credited mitigation — parameterization, argv-no-shell, sanitizer, allow-list, path/scheme
validation, authz guard, non-privileged context — forces FP). Confidence ≥ 0.7 to report; `<0.7` →
Suppressed. If a component has many candidates, fan out with Explore/subagents per component. Then run
the **consistency-validation** sweep across the whole set before writing (same sink+mitigation ⇒ same
verdict; every REAL carries its evidence chain; severity ranks, never decides).

Record into the same consolidated `findings-<TODAY>.md` as a `## Whole-repo audit` section, grouped by
component, each finding: component | sink (file:line) | untrusted source | class | severity |
confidence | REAL/UNCERTAIN | action — plus the Suppressed sub-list and the "not audited + why" note
from Stage 2 (coverage is a claim; state its limits).

## Transparency contract
- Before any deep pass: say "running `<skill>` because `<signal>` (token-costly)" and let the
  user skip it.
- Never run a deep pass with no basis just to be thorough — that's the cadence violation this
  orchestrator exists to avoid.

## Boundaries (HARD)
- Produces **internal evidence**; does NOT replace an external ASV scan or a pentest.
- It orchestrates the other skills' judgment — it does not lower their bars (confidence gate,
  reachability, exclusions all still apply).
- The whole-repo blueprint is **targeted, not exhaustive**: a clean audit means "nothing found in
  the components/classes audited this round", never "no flaws". Its Stage-2 "not audited + why" note
  is part of the report, not an omission — a cutover gate still needs a pentest.
