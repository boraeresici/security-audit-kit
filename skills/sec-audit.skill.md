---
name: sec-audit
description: One-command security audit orchestrator. Runs the deterministic scan, triages the findings, and (SIGNAL-GATED, not blindly) runs the deep judgment passes that actually apply to this repo, consolidating everything into one findings file. Use it when you want "just audit this" without deciding which skill to run — e.g. "audit this repo", "run a security review", before a PR / cutover.
---

# sec-audit — one-command audit orchestrator

The single entry point so you don't have to remember *which* skill to run. It drives the
deterministic scan + the judgment skills (`sec-triage`, `sec-sast-deep`, `sec-ai-review`,
`sec-threat-model`) and produces **one** consolidated `findings-<TODAY>.md`. You run it; you
read the final report.

**Cost discipline (important):** the deep passes are token-costly and are NOT run every time.
Default = scan + triage only. A deep pass runs **only** when a clear signal in the repo calls
for it (below), or when you explicitly ask (`deep` / "run everything"). Always announce which
deep passes you will run and **why** before running them.

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

## Transparency contract
- Before any deep pass: say "running `<skill>` because `<signal>` (token-costly)" and let the
  user skip it.
- Never run a deep pass with no basis just to be thorough — that's the cadence violation this
  orchestrator exists to avoid.

## Boundaries (HARD)
- Produces **internal evidence**; does NOT replace an external ASV scan or a pentest.
- It orchestrates the other skills' judgment — it does not lower their bars (confidence gate,
  reachability, exclusions all still apply).
