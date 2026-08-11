#!/usr/bin/env bash
# tests/eval/run.sh — run the sec-triage REAL/FP eval and report precision/recall.
#
# DEV-ONLY (not part of scan.sh; not vendored into a consumer's scan path). Measures the skills'
# judgment against tests/eval/cases.yaml so prompt/methodology changes (Phase A) and any future
# local/other-provider backend can be graded on the SAME corpus before being trusted.
#
# Requires: node/npx + a provider API key (default provider = Anthropic -> ANTHROPIC_API_KEY).
# Skips cleanly (exit 0) if the toolchain/key is absent, so CI/e2e never hard-fail on it.
#
# Usage:  bash tests/eval/run.sh [extra promptfoo args...]
# Regression gates (optional):  EVAL_MIN_RECALL=0.9 EVAL_MIN_PRECISION=0.8 bash tests/eval/run.sh
# Alternate backend on the SAME corpus (Tier-L comparison), e.g. GLM-5.2:
#   EVAL_CONFIG=promptfooconfig.glm.yaml EVAL_OUT=output.glm.json bash tests/eval/run.sh
# NVIDIA NIM (GLM-5.2, OpenAI-compatible endpoint; needs NVIDIA_API_KEY):
#   EVAL_CONFIG=promptfooconfig.nim.yaml EVAL_OUT=output.nim.json bash tests/eval/run.sh
set -uo pipefail
cd "$(dirname "$0")" || exit 1

PROMPTFOO_VER="0.121.17"   # pinned (no drift)
CONFIG="${EVAL_CONFIG:-promptfooconfig.yaml}"
# Split selection: the corpus carries `metadata.split: dev|holdout` and both files are loaded by
# every config, so we pick one at run time with --filter-metadata. Default is the dev (tuning)
# split; the headline number comes from `EVAL_SPLIT=holdout`, which must not be looked at while
# iterating the prompt. Output file defaults per split so a dev run never clobbers a holdout result.
SPLIT="${EVAL_SPLIT:-dev}"
case "$SPLIT" in dev|holdout) ;; *) echo "[eval] ERROR: EVAL_SPLIT must be dev|holdout, got: $SPLIT"; exit 2;; esac
# Default output name is derived from the backend + split so distinct runs never clobber each other
# (e.g. promptfooconfig.nim.yaml + holdout -> output.nim.holdout.json; the base config -> output.json).
# EVAL_OUT still overrides. Tag = the config's middle segment, empty for the base promptfooconfig.yaml.
TAG="$(basename "$CONFIG" .yaml)"; TAG="${TAG#promptfooconfig}"; TAG="${TAG#.}"
OUT="${EVAL_OUT:-output${TAG:+.$TAG}$([ "$SPLIT" = holdout ] && echo .holdout).json}"
have(){ command -v "$1" >/dev/null 2>&1; }

have npx || { echo "[eval] SKIP: node/npx not installed (dev-only harness)"; exit 0; }
have node || { echo "[eval] SKIP: node not installed"; exit 0; }
[ -f "$CONFIG" ] || { echo "[eval] SKIP: config not found: $CONFIG"; exit 0; }

# Optional: load provider keys from a gitignored env file — first match wins, searched in
# order: tests/eval/.env.local, tests/eval/.env, repo root .env.local, repo root .env.
# All are covered by .gitignore (**.env**) so keys never reach git. NOTE: the file is sourced
# as shell (KEY=value lines only, no quotes needed) — keep it trivial and never commit it.
for envf in ./.env.local ./.env ../../.env.local ../../.env; do
  if [ -f "$envf" ]; then
    # A variable the CALLER set wins over the file — including one deliberately set to EMPTY.
    # e2e blanks the provider keys precisely so a test run can never turn into a live, costed
    # eval; sourcing the file unconditionally would defeat that guard on any dev box that has
    # an .env.local. Snapshot the caller's values, source, then restore them.
    _preset=""
    while IFS='=' read -r _k _; do
      case "$_k" in ''|\#*|*[!A-Za-z0-9_]*) continue ;; esac
      if eval "[ -n \"\${$_k+x}\" ]"; then
        eval "_PRESET_$_k=\"\$$_k\""
        _preset="$_preset $_k"
      fi
    done < "$envf"
    set -a
    # shellcheck disable=SC1090,SC1091
    . "$envf"
    set +a
    for _k in $_preset; do eval "export $_k=\"\$_PRESET_$_k\""; done
    echo "[eval] loaded provider keys from $envf${_preset:+ (kept caller-set:$_preset)}"
    break
  fi
done

# Provider key checks. Anthropic providers need ANTHROPIC_API_KEY; OpenAI-compatible
# providers declare their key env var in the config as `apiKeyEnvar:`.
if ! grep -q 'providers:' "$CONFIG"; then echo "[eval] SKIP: no providers in config"; exit 0; fi
if grep -qE 'id:\s*anthropic:' "$CONFIG" && [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  echo "[eval] SKIP: ANTHROPIC_API_KEY not set (needed for the Anthropic provider)"; exit 0
fi
while IFS= read -r envar; do
  [ -n "$envar" ] || continue
  if [ -z "${!envar:-}" ]; then
    echo "[eval] SKIP: $envar not set (declared as apiKeyEnvar in $CONFIG)"; exit 0
  fi
done < <(grep -oE 'apiKeyEnvar:[[:space:]]*[A-Za-z_][A-Za-z_0-9]*' "$CONFIG" | sed 's/.*:[[:space:]]*//')

# Copy-paste guard: interactive zsh without interactive_comments passes a trailing
# "# comment" through as real arguments — drop a literal "#" and everything after it.
pass=()
for a in "$@"; do [ "$a" = "#" ] && break; pass+=("$a"); done

rm -f "$OUT"   # never let score.mjs read a stale result from a previous run
# Concurrency: free-tier endpoints (NIM / z.ai) rate-limit at the default 4, which shows up as
# provider errors, not a bad score (score.mjs excludes them). Override with EVAL_CONCURRENCY.
CONC="${EVAL_CONCURRENCY:-4}"
echo "[eval] promptfoo@$PROMPTFOO_VER — grading $SPLIT split via $CONFIG -> $OUT (concurrency $CONC)"
npx -y "promptfoo@$PROMPTFOO_VER" eval -c "$CONFIG" -o "$OUT" --no-progress-bar \
  --filter-metadata "split=$SPLIT" -j "$CONC" ${pass[@]+"${pass[@]}"} || true
node score.mjs "$OUT"
