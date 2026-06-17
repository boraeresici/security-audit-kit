#!/usr/bin/env bash
# security-audit-kit / install.sh — one-command install into a new project.
#
#   1) Copy this folder into the target repo:  tools/security-audit-kit/
#   2) Run from the repo root:                 bash tools/security-audit-kit/install.sh
#
# What it does: prerequisite check -> enable git hooks (core.hooksPath)
#               -> install the sec-triage skill into .claude/skills/ -> usage summary.
# Idempotent: safe to re-run.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || { echo "ERROR: not a git repo. Run 'git init' first."; exit 1; }
KIT_REL="tools/security-audit-kit"
KIT="$ROOT/$KIT_REL"
[ -d "$KIT" ] || { echo "ERROR: $KIT_REL not found. Copy the kit there first."; exit 1; }

ok(){ printf '  \033[32mok\033[0m  %s\n' "$1"; }
miss(){ printf '  \033[33m--\033[0m  %s\n' "$1"; }
have(){ command -v "$1" >/dev/null 2>&1; }

echo "== prerequisite check (a missing one only skips that dimension; install still runs) =="
have docker && ok "docker (gitleaks/trivy/syft)" || miss "docker MISSING -> secret/container/sbom skipped"
{ have uvx || have pipx; } && ok "uvx/pipx (semgrep/checkov/pip-audit)" || miss "uvx/pipx MISSING -> sast/iac/py-deps skipped"
{ have pnpm || have yarn || have npm; } && ok "js package manager (js-deps)" || miss "js package manager MISSING -> js-deps skipped"

echo "== hooks =="
chmod +x "$KIT/scan.sh" "$KIT/hooks/pre-commit" "$KIT/hooks/pre-push"
# Point hooksPath directly at the kit to avoid clashing with existing .git/hooks.
git config core.hooksPath "$KIT_REL/hooks"
ok "core.hooksPath -> $KIT_REL/hooks (pre-commit=fast, pre-push=all)"

echo "== project config =="
if [ -f "$ROOT/.security-audit.conf" ]; then
  ok ".security-audit.conf already exists (preserved)"
else
  cp "$KIT/security-audit.conf.example" "$ROOT/.security-audit.conf"
  ok ".security-audit.conf created (from example) -> edit SAST_PATHS etc. + commit it"
fi
if [ -f "$ROOT/.security-exclusions.md" ]; then
  ok ".security-exclusions.md already exists (preserved)"
else
  cp "$KIT/exclusions.example.md" "$ROOT/.security-exclusions.md"
  ok ".security-exclusions.md created (from example) -> triage reads it to drop noise + commit it"
fi

echo "== Claude skills =="
# Source templates live in the kit under skills/; they are installed into the TARGET
# repo as .claude/skills/<name>/SKILL.md (the path Claude Code discovers skills from).
mkdir -p "$ROOT/.claude/skills/sec-triage"
cp "$KIT/skills/sec-triage.skill.md" "$ROOT/.claude/skills/sec-triage/SKILL.md"
ok ".claude/skills/sec-triage/SKILL.md (finding triage)"
mkdir -p "$ROOT/.claude/skills/sec-sast-deep"
cp "$KIT/skills/sec-sast-deep.skill.md" "$ROOT/.claude/skills/sec-sast-deep/SKILL.md"
ok ".claude/skills/sec-sast-deep/SKILL.md (semantic SAST: authz/IDOR/logic)"
mkdir -p "$ROOT/.claude/skills/sec-ai-review"
cp "$KIT/skills/sec-ai-review.skill.md" "$ROOT/.claude/skills/sec-ai-review/SKILL.md"
ok ".claude/skills/sec-ai-review/SKILL.md (AI/LLM security: prompt injection/agency)"
mkdir -p "$ROOT/docs/security/scan-findings" 2>/dev/null || true

echo "== integrity =="
# Advisory (not fatal): confirm the vendored kit matches its CHECKSUMS manifest. A modified
# fork without a regenerated manifest will warn here — that is expected; review and proceed.
if [ -f "$KIT/CHECKSUMS" ]; then
  if bash "$KIT/scan.sh" verify >/dev/null 2>&1; then
    ok "scan.sh verify: kit files match CHECKSUMS"
  else
    miss "scan.sh verify: MISMATCH — run 'bash $KIT_REL/scan.sh verify' and review before trusting"
  fi
else
  miss "no CHECKSUMS manifest (older kit or a fork) -> skipping integrity check"
fi

cat <<EOF

== install complete ==
  ad-hoc scan   : bash $KIT_REL/scan.sh all      (or: fast|deps|secret|sast|changed|iac|container|sbom)
  every commit  : pre-commit runs a staged-secret scan; + 'deps' when a manifest changes
  before a PR   : pre-push automatically runs 'all'
  finding triage: /sec-triage in Claude  -> docs/security/scan-findings/findings-<date>.md
  deep SAST     : /sec-sast-deep in Claude (authz/IDOR/logic; pre-cutover / after a new endpoint)
  AI/LLM review : /sec-ai-review in Claude (prompt injection/agency; if the code calls an LLM)
  emergency bypass: SKIP_SECURITY=1 git commit   |   git push --no-verify

HARD boundary: produces internal evidence; does NOT replace an ASV scan + pentest.
EOF
