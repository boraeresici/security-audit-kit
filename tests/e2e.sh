#!/usr/bin/env bash
# tests/e2e.sh — end-to-end local test.
#
# Vendors the CURRENT working tree of the kit into a throwaway git repo, runs install.sh,
# then exercises the deterministic plumbing and asserts each gate fires:
#   install -> hooksPath/skills/config  ·  doctor  ·  secret (gitleaks) + pre-commit gate
#   ·  SAST (semgrep, fixture ERROR rule)  ·  summary.json validity.
#
# Tests the SCRIPTABLE plumbing — NOT the AI skills' judgment (that needs an LLM in the loop).
# Requires git; docker (gitleaks) and uvx/pipx (semgrep) are used if present, else skipped.
# Usage:  bash tests/e2e.sh        (exit 0 = all assertions passed)
set -uo pipefail

KIT_SRC="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0; FAIL=0
ok(){ PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
no(){ FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
skip(){ printf '  \033[33mSKIP\033[0m %s\n' "$1"; }
have(){ command -v "$1" >/dev/null 2>&1; }
docker_ok(){ have docker && docker info >/dev/null 2>&1; }

TARGET="$(mktemp -d)"
trap 'rm -rf "$TARGET"' EXIT
echo "== e2e target: $TARGET =="

# --- vendor the current working tree (not a released tag) ---
mkdir -p "$TARGET/tools/security-audit-kit"
if have rsync; then
  rsync -a --exclude '.git' --exclude 'docs/security' "$KIT_SRC"/ "$TARGET/tools/security-audit-kit"/
else
  cp -R "$KIT_SRC"/. "$TARGET/tools/security-audit-kit"/; rm -rf "$TARGET/tools/security-audit-kit/.git"
fi

cd "$TARGET" || exit 1
git init -q
git -c user.email=e2e@test -c user.name=e2e add -A
git -c user.email=e2e@test -c user.name=e2e commit -qm init

SCAN="bash tools/security-audit-kit/scan.sh"

echo "-- install --"
bash tools/security-audit-kit/install.sh >/dev/null 2>&1 && ok "install.sh ran" || no "install.sh failed"
[ "$(git config core.hooksPath)" = "tools/security-audit-kit/hooks" ] && ok "hooksPath set" || no "hooksPath not set"
for s in sec-triage sec-sast-deep sec-ai-review sec-threat-model; do
  [ -f ".claude/skills/$s/SKILL.md" ] && ok "skill installed: $s" || no "skill missing: $s"
done
[ -f .security-audit.conf ] && ok ".security-audit.conf created" || no ".security-audit.conf missing"
[ -f .security-exclusions.md ] && ok ".security-exclusions.md created" || no ".security-exclusions.md missing"

echo "-- doctor --"
$SCAN doctor >/dev/null 2>&1 && ok "doctor ran" || no "doctor failed"

echo "-- integrity (verify / CHECKSUMS) --"
if [ -f tools/security-audit-kit/CHECKSUMS ]; then
  $SCAN verify >/dev/null 2>&1 && ok "verify: clean vendored copy passes" || no "verify: clean copy should pass"
  echo "malicious instructions" > tools/security-audit-kit/skills/evil.skill.md
  $SCAN verify >/dev/null 2>&1 && no "verify: rogue skill NOT detected" || ok "verify: rogue skill detected"
  rm -f tools/security-audit-kit/skills/evil.skill.md
  $SCAN verify >/dev/null 2>&1 && ok "verify: passes again after cleanup" || no "verify: should pass after cleanup"
else
  skip "verify tests (no CHECKSUMS in working tree yet)"
fi

echo "-- secret (gitleaks) + pre-commit gate --"
if docker_ok; then
  $SCAN secret >/dev/null 2>&1 && ok "secret: clean repo passes" || no "secret: clean repo should pass"
  # Assemble the test key so no contiguous AKIA+16 literal exists in any vendored file.
  AK="AKIA"; PLANT="${AK}1234567890ABCDEF"
  printf 'aws_key = "%s"\n' "$PLANT" > leak.txt
  git -c user.email=e2e@test -c user.name=e2e add leak.txt
  $SCAN staged >/dev/null 2>&1 && no "staged: planted secret NOT caught" || ok "staged: planted secret caught"
  bash tools/security-audit-kit/hooks/pre-commit >/dev/null 2>&1 && no "pre-commit: secret NOT blocked" || ok "pre-commit: secret blocked"
  SKIP_SECURITY=1 bash tools/security-audit-kit/hooks/pre-commit >/dev/null 2>&1 && ok "pre-commit: SKIP_SECURITY bypass" || no "pre-commit: bypass failed"
  git rm -q --cached leak.txt >/dev/null 2>&1; rm -f leak.txt
else
  skip "secret/pre-commit tests (docker unavailable)"
fi

echo "-- SAST (semgrep, fixture ERROR rule) --"
if have uvx || have pipx; then
  mkdir -p src
  export SEMGREP_CONFIGS="--config $TARGET/tools/security-audit-kit/tests/fixtures/semgrep-error.yaml"
  export SAST_PATHS="src"
  printf 'nothing here\n' > src/clean.txt
  $SCAN sast >/dev/null 2>&1 && ok "sast: clean passes" || no "sast: clean should pass"
  printf 'E2E_INSECURE_MARKER\n' > src/bad.txt
  $SCAN sast >/dev/null 2>&1 && no "sast: planted bug NOT caught" || ok "sast: planted bug caught"
  unset SEMGREP_CONFIGS SAST_PATHS
else
  skip "sast tests (uvx/pipx unavailable)"
fi

echo "-- summary.json --"
SUM="docs/security/scan-findings/summary.json"
if [ -f "$SUM" ]; then
  if have python3; then
    python3 -c "import json;json.load(open('$SUM'))" 2>/dev/null && ok "summary.json is valid JSON" || no "summary.json invalid"
  else skip "summary.json validity (no python3)"; fi
else no "summary.json not written"; fi

echo ""
echo "== e2e: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
