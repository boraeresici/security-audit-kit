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
set -uo pipefail
cd "$(dirname "$0")" || exit 1

PROMPTFOO_VER="0.121.17"   # pinned (no drift)
CONFIG="${EVAL_CONFIG:-promptfooconfig.yaml}"
OUT="${EVAL_OUT:-output.json}"
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
    set -a
    # shellcheck disable=SC1090,SC1091
    . "$envf"
    set +a
    echo "[eval] loaded provider keys from $envf"
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
echo "[eval] promptfoo@$PROMPTFOO_VER — grading tests/eval/cases.yaml via $CONFIG"
npx -y "promptfoo@$PROMPTFOO_VER" eval -c "$CONFIG" -o "$OUT" --no-progress-bar ${pass[@]+"${pass[@]}"} || true
node score.mjs "$OUT"
