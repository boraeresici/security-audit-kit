# Eval harness — skill judgment regression (dev-only)

Measures the **`sec-triage` REAL/FP judgment** against a labeled corpus so we can tell whether a
change actually *improves* the AI layer — not just "looks reasonable". This is **Tier-L L1** in the
roadmap and the gate for the Phase-A skill work and any future local / other-provider backend:
never wire a model or a prompt change into the flow before measuring it here.

**Not part of `scan.sh`.** Dev/maintainer tool only; never runs in a consumer's scan path.

## What it does
`cases.yaml` + `cases.holdout.yaml` are a labeled corpus of scanner findings (REAL exploitable +
FALSE POSITIVES across the classes `sec-triage` must suppress: test-only, not-reachable,
dev-placeholder, safe-parameterized, allow-listed, sanitized, vendored, docs-example, and more —
split into a dev/tuning and a held-out set; see below). `run.sh` feeds each case + the triage
judgment prompt
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
ANTHROPIC_API_KEY=... bash tests/eval/run.sh                 # dev split (default)
ANTHROPIC_API_KEY=... EVAL_SPLIT=holdout bash tests/eval/run.sh   # held-out = reportable number
# regression gates (exit 1 if unmet):
ANTHROPIC_API_KEY=... EVAL_MIN_RECALL=0.9 EVAL_MIN_PRECISION=0.8 bash tests/eval/run.sh
```

## Provider swap (the local-model / provider-agnostic de-risk)
Edit `providers:` in `promptfooconfig.yaml` to point at a candidate backend (e.g.
`ollama:chat:llama3.1`, an OpenAI model, or a LiteLLM endpoint) and re-run against the SAME corpus
to compare it head-to-head with the Claude baseline. This is exactly the measurement Tier-L / the
provider-agnostic plan (`AI-JUDGMENT-DESIGN.local.md`) require before trusting a weaker/local model.

### Shipped backend variants
Each variant is the same prompt + corpus + grader — only the provider differs, so scores are
directly comparable. Set the matching key in `tests/eval/.env.local` (gitignored) and run:

| Backend | Config | Key env var | Run (add `EVAL_SPLIT=holdout` for the reportable number) |
|---|---|---|---|
| Anthropic Claude (default) | `promptfooconfig.yaml` | `ANTHROPIC_API_KEY` | `bash tests/eval/run.sh` |
| GLM-5.2 via NVIDIA NIM | `promptfooconfig.nim.yaml` | `NVIDIA_API_KEY` | `EVAL_CONFIG=promptfooconfig.nim.yaml bash tests/eval/run.sh` |
| GLM-5.2 via Z.ai | `promptfooconfig.glm.yaml` | `ZAI_API_KEY` | `EVAL_CONFIG=promptfooconfig.glm.yaml bash tests/eval/run.sh` |
| Mistral Large 3 | `promptfooconfig.mistral.yaml` | `MISTRAL_API_KEY` | `EVAL_CONFIG=promptfooconfig.mistral.yaml bash tests/eval/run.sh` |

All configs point at ONE grader (`grade.mjs` via `file://`), so a scoring change can never land on
some backends and not others — that would silently make cross-backend scores non-comparable.
Declare a new backend as an OpenAI-compatible provider (`apiBaseUrl` + `apiKeyEnvar`) rather than a
native promptfoo provider id: `run.sh`'s clean-skip guard only recognises the anthropic id and a
declared key-env-var line, so a native id hard-fails instead of skipping when the key is absent.

### Dev / held-out split
The corpus is 61 cases in two files, and the split is enforced mechanically — every config loads
both and `run.sh` selects one with `--filter-metadata split=<dev|holdout>`:

- **`cases.yaml`** — 31-case **dev split** (`EVAL_SPLIT=dev`, the default). The tuning surface: you
  may iterate the prompt against these. Scores here are training scores, optimistically biased.
- **`cases.holdout.yaml`** — 30-case **held-out split** (`EVAL_SPLIT=holdout`, writes
  `output.holdout.json`). The reportable number. **Do not read it while tuning the prompt** — the
  moment you edit the prompt in response to a holdout failure, it stops being held out. Fix the
  prompt against a *new* dev case that captures the same rule, then re-measure.

Most REAL cases have an FP **twin**: same vuln class, differing by one decisive property (sanitizer,
allow-list, reachability, safe API variant), tagged `difficulty: hard`. Twins are what give the
corpus resolving power — without them, every FP is obvious and the score saturates at 100%.

> **Interpretation warning:** 15 REAL cases per split ⇒ one flip moves recall ~6.7pp. Scores are
> directional; do **not** rank backends off them (roadmap L1b/L1c).

> **NIM result (2026-07-10):** GLM-5.2 (`z-ai/glm-5.2` via NIM), 0 errors on both splits.
> Dev split: 31/31 (100% everything). **Held-out split: precision 83.3%, recall 100%, F1 90.9%,
> accuracy 90% — TP=15, FP=3, FN=0, TN=12.** All three FP→REAL misses are `difficulty: hard` FP
> twins (safe-argv subprocess, `pull_request` CI workflow, path-validated zip extraction): GLM got
> every REAL counterpart right but over-flagged the safe twins. Report the held-out row, not the
> dev row. See `docs/compare/aikido-semgrep.md`.
>
> **The Claude default backend is still unmeasured.** The key authenticates, but every inference
> call returns `credit balance is too low` (400).
>
> **Free-tier rate limits:** NIM / z.ai return provider errors at the default concurrency 4 (score.mjs
> excludes them, so a rate-limited run reports on fewer cases). Add `EVAL_CONCURRENCY=2` if you see them.

**Provider errors are never scored.** A case that never reached the model (auth, billing, network,
bad model id — promptfoo's `failureReason=2`) carries no information about judgment quality, so
`score.mjs` refuses to report and exits **2** rather than charging the failure to the model. An
all-errored run used to print a plausible-looking `0%`; a partially-errored one would have skewed
every metric. Use `EVAL_ALLOW_PARTIAL=1` to score only the cases that did run. Exit codes: **0** ok,
**1** regression gate unmet (`EVAL_MIN_*`), **2** no usable data.

> An unparseable *answer* is still charged to the model (REAL→FN, FP→FP) — the model replied, it
> just replied unreadably. Only a failed *request* is excluded.

## Extending the corpus
Keep code as embedded **strings** and any secret an obvious placeholder, so fixtures never trip the
kit's own self-audit. Each case needs `metadata: { label, vuln_class, split, difficulty, ... }`
(FP cases also `fp_class`); `split` and `difficulty` are what the harness and reporting rely on.

- **Adding dev cases** (`cases.yaml`): free to do anytime; prefer FP *twins* of existing REAL cases.
- **Adding held-out cases** (`cases.holdout.yaml`): only ever *add* — never edit or delete a case
  because a model failed it. That is how a test set is quietly rewritten into a training set. If a
  held-out case exposes a genuine prompt gap, encode the fix as a *new dev case* and re-measure.
- **Avoid literal `{{ }}`** in case code except valid GitHub Actions `${{ … }}` expressions:
  promptfoo renders cases through Nunjucks, and a brace-pair with a colon (e.g. JSX
  `dangerouslySetInnerHTML={{ __html: x }}`) is a template syntax error. Add a space: `={ { … } }`.

Grow coverage: more vuln classes, real-CVE snippets, and (later) separate corpora + prompts for
`sec-sast-deep` / `sec-ai-review`.

## Files
- `cases.yaml` — dev/tuning split (promptfoo tests).
- `cases.holdout.yaml` — held-out split; the reportable number. Do not read while tuning.
- `triage_prompt.md` — the judgment prompt (mirrors `sec-triage` Pass 1/2).
- `promptfooconfig.yaml` — prompts + provider + grader ref (`promptfooconfig.<backend>.yaml` for variants).
- `grade.mjs` — the shared REAL/FP grader every config points at (`export default (output, context)`).
- `score.mjs` — precision/recall from promptfoo output; excludes provider errors (zero deps).
- `run.sh` — env-gated orchestration (`EVAL_SPLIT`, `EVAL_CONFIG`, `EVAL_CONCURRENCY`, `EVAL_MIN_*`).
- `output.json` / `output.holdout.json` — the last run's raw results per split (gitignored).
