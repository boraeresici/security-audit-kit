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
set -uo pipefail
cd "$(dirname "$0")" || exit 1

PROMPTFOO_VER="0.121.17"   # pinned (no drift)
have(){ command -v "$1" >/dev/null 2>&1; }

have npx || { echo "[eval] SKIP: node/npx not installed (dev-only harness)"; exit 0; }
have node || { echo "[eval] SKIP: node not installed"; exit 0; }

# Provider key check — default provider is Anthropic. If you swap providers in
# promptfooconfig.yaml, adjust/relax this check accordingly.
if ! grep -q 'providers:' promptfooconfig.yaml; then echo "[eval] SKIP: no providers in config"; exit 0; fi
if grep -qE 'id:\s*anthropic:' promptfooconfig.yaml && [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  echo "[eval] SKIP: ANTHROPIC_API_KEY not set (needed for the Anthropic provider)"; exit 0
fi

echo "[eval] promptfoo@$PROMPTFOO_VER — grading tests/eval/cases.yaml"
npx -y "promptfoo@$PROMPTFOO_VER" eval -c promptfooconfig.yaml -o output.json --no-progress-bar "$@" || true
node score.mjs output.json
