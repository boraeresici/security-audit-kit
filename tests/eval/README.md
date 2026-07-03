# Eval harness — skill judgment regression (dev-only)

Measures the **`sec-triage` REAL/FP judgment** against a labeled corpus so we can tell whether a
change actually *improves* the AI layer — not just "looks reasonable". This is **Tier-L L1** in the
roadmap and the gate for the Phase-A skill work and any future local / other-provider backend:
never wire a model or a prompt change into the flow before measuring it here.

**Not part of `scan.sh`.** Dev/maintainer tool only; never runs in a consumer's scan path.

## What it does
`cases.yaml` is a labeled corpus of scanner findings (5 REAL exploitable + 5 FALSE POSITIVES that
match the exact classes `sec-triage` must suppress: test-only, not-reachable, dev-placeholder,
safe-parameterized, allow-listed). `run.sh` feeds each case + the triage judgment prompt
(`triage_prompt.md`, a provider-neutral distillation of the skill's Pass 1/2) to a model via
[promptfoo](https://promptfoo.dev) (pinned), then `score.mjs` reports a confusion matrix +
**precision / recall / F1 / accuracy** for the REAL class.

- **Recall** = of true REAL findings, how many were caught (a drop here = the dangerous regression:
  the model silently downgrading real issues to FP).
- **Precision** = of findings called REAL, how many truly are (noise / over-flagging).

## Requirements
- `node` / `npx` (promptfoo is pinned and fetched via `npx -y`).
- A provider API key — default provider is Anthropic → set `ANTHROPIC_API_KEY`.
- Missing toolchain/key ⇒ `run.sh` **skips cleanly (exit 0)**; it never hard-fails CI/e2e.

## Run
```sh
ANTHROPIC_API_KEY=... bash tests/eval/run.sh
# regression gates (exit 1 if unmet):
ANTHROPIC_API_KEY=... EVAL_MIN_RECALL=0.9 EVAL_MIN_PRECISION=0.8 bash tests/eval/run.sh
```

## Provider swap (the local-model / provider-agnostic de-risk)
Edit `providers:` in `promptfooconfig.yaml` to point at a candidate backend (e.g.
`ollama:chat:llama3.1`, an OpenAI model, or a LiteLLM endpoint) and re-run against the SAME corpus
to compare it head-to-head with the Claude baseline. This is exactly the measurement Tier-L / the
provider-agnostic plan (`AI-JUDGMENT-DESIGN.local.md`) require before trusting a weaker/local model.

## Extending the corpus
Add cases to `cases.yaml` (keep code as embedded **strings** and any secret an obvious placeholder,
so fixtures never trip the kit's own self-audit). Grow coverage: more vuln classes, real-CVE
snippets, and (later) separate corpora + prompts for `sec-sast-deep` / `sec-ai-review`.

## Files
- `cases.yaml` — labeled corpus (promptfoo tests).
- `triage_prompt.md` — the judgment prompt (mirrors `sec-triage` Pass 1/2).
- `promptfooconfig.yaml` — prompts + provider + per-case grader.
- `score.mjs` — precision/recall from promptfoo output (zero deps).
- `run.sh` — env-gated orchestration.
- `output.json` — the last run's raw results (gitignored).
