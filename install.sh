#!/usr/bin/env bash
# security-audit-kit / install.sh — one-command install into a new project.
#
#   1) Copy this folder into the target repo:  tools/security-audit-kit/
#   2) Run from the repo root:                 bash tools/security-audit-kit/install.sh
#
# What it does: prerequisite check -> enable git hooks (core.hooksPath)
#               -> install the sec-triage skill into .claude/skills/ -> usage summary.
# Idempotent: safe to re-run.  Undo: install.sh --uninstall
#
# Existing hooks are never silenced (F10). A repo that already runs hooks (.git/hooks, a custom
# core.hooksPath such as .husky, the pre-commit framework) gets them CHAINED: core.hooksPath points
# at generated wrappers in .git/security-audit-hooks that run the kit's hook, then the repo's own,
# with the same arguments and stdin. What install changed is recorded in
# .git/security-audit-install.state, so --uninstall can restore exactly that and nothing else.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || { echo "ERROR: not a git repo. Run 'git init' first."; exit 1; }
KIT_REL="tools/security-audit-kit"
KIT="$ROOT/$KIT_REL"
[ -d "$KIT" ] || { echo "ERROR: $KIT_REL not found. Copy the kit there first."; exit 1; }

ok(){ printf '  \033[32mok\033[0m  %s\n' "$1"; }
miss(){ printf '  \033[33m--\033[0m  %s\n' "$1"; }
have(){ command -v "$1" >/dev/null 2>&1; }

# --skills-only: install skills/config but DON'T touch git hooks (for teams driving the
# triggers via the pre-commit framework, which would clash with core.hooksPath).
SKILLS_ONLY=0
# --with-agent-hook: also wire the PreToolUse package check into .claude/settings.json. OPT-IN by
# design — it runs on every Bash tool call the agent makes, and silently editing a consumer's
# agent settings is not something an installer should do on its own.
AGENT_HOOK=0
UNINSTALL=0
for arg in "$@"; do
  case "$arg" in
    --skills-only)     SKILLS_ONLY=1 ;;
    --with-agent-hook) AGENT_HOOK=1 ;;
    --uninstall)       UNINSTALL=1 ;;
    "") ;;
    *) echo "unknown option: $arg (usage: install.sh [--skills-only] [--with-agent-hook] | --uninstall)"; exit 2 ;;
  esac
done

# ---- install record (F10) -------------------------------------------------------------------
GITDIR="$(cd "$ROOT" && git rev-parse --git-common-dir)"; case "$GITDIR" in /*) ;; *) GITDIR="$ROOT/$GITDIR" ;; esac
STATE="$GITDIR/security-audit-install.state"
CHAIN_DIR="$GITDIR/security-audit-hooks"
KIT_HOOKS="$KIT_REL/hooks"
SKILLS="sec-triage sec-sast-deep sec-ai-review sec-threat-model sec-audit"
state_get(){ [ -f "$STATE" ] || return 0; sed -n "s/^$1=//p" "$STATE" | tail -1; }   # no record = empty, never a failure (set -e)
state_set(){ local tmp; tmp="$(mktemp)"; { [ -f "$STATE" ] && grep -v "^$1=" "$STATE"; printf '%s=%s\n' "$1" "$2"; } > "$tmp"; mv -f "$tmp" "$STATE"; }
fsum(){ cksum < "$1" | awk '{print $1"-"$2}'; }
HOOK_CMD="bash \"\$CLAUDE_PROJECT_DIR/$KIT_REL/hooks/pre-tool-install.sh\""

# Remove only what install added, as recorded; keep the team's config and anything edited since.
uninstall(){
  echo "== uninstall =="
  local legacy=0 cur prev s f sum
  if [ ! -f "$STATE" ]; then
    # Without a record, only what is recognisably the kit's counts: its hooks dir as hooksPath, or a
    # skill identical to the kit's template. A skill kept because it was edited is the user's now.
    cur="$(git config --get core.hooksPath 2>/dev/null || true)"
    local kits=0
    for s in $SKILLS; do
      f="$ROOT/.claude/skills/$s/SKILL.md"
      [ -f "$f" ] && [ "$(fsum "$f")" = "$(fsum "$KIT/skills/$s.skill.md")" ] && kits=1
    done
    if [ "$cur" != "$KIT_HOOKS" ] && [ "$kits" = 0 ]; then
      ok "nothing to undo (no install record in .git, no kit hooks or unedited kit skills)"; return 0
    fi
    legacy=1; miss "no install record (installed by a kit older than this one) -> undoing what can be told apart safely"
  fi
  cur="$(git config --get core.hooksPath 2>/dev/null || true)"
  if [ "$cur" = "$KIT_HOOKS" ] || [ "$cur" = "$CHAIN_DIR" ]; then
    prev="$(state_get prev_hooks_path)"
    if [ -z "$prev" ] || [ "$prev" = "-unset-" ]; then git config --unset core.hooksPath; ok "core.hooksPath unset (as before install)"
    else git config core.hooksPath "$prev"; ok "core.hooksPath -> $prev (as before install)"; fi
  elif [ -n "$cur" ]; then
    miss "core.hooksPath is '$cur' (changed since install) -> left as is"
  fi
  [ -d "$CHAIN_DIR" ] && rm -rf "$CHAIN_DIR" && ok "removed the hook wrappers (.git/security-audit-hooks)"
  for s in $SKILLS; do
    f="$ROOT/.claude/skills/$s/SKILL.md"; [ -f "$f" ] || continue
    if [ "$legacy" = 1 ]; then sum="$(fsum "$KIT/skills/$s.skill.md")"; else sum="$(state_get "skill_$s")"; fi
    if [ -n "$sum" ] && [ "$(fsum "$f")" = "$sum" ]; then
      rm -f "$f"; rmdir "$ROOT/.claude/skills/$s" 2>/dev/null || true; ok "removed .claude/skills/$s"
    else
      miss "kept .claude/skills/$s/SKILL.md — it was edited after install (delete it yourself if you want)"
    fi
  done
  rmdir "$ROOT/.claude/skills" "$ROOT/.claude" 2>/dev/null || true
  if [ "$(state_get agent_hook)" = 1 ] && [ -f "$ROOT/.claude/settings.json" ] && have python3; then
    SETTINGS="$ROOT/.claude/settings.json" HOOKCMD="$HOOK_CMD" python3 - <<'PYEOF2' && ok "removed the agent hook from .claude/settings.json" || miss ".claude/settings.json left as is (not valid JSON?)"
import json, os, pathlib
path = pathlib.Path(os.environ["SETTINGS"]); cmd = os.environ["HOOKCMD"]
doc = json.loads(path.read_text() or "{}")
pre = doc.get("hooks", {}).get("PreToolUse", [])
for m in pre:
    m["hooks"] = [h for h in m.get("hooks", []) if h.get("command") != cmd]
pre[:] = [m for m in pre if m.get("hooks")]
if not pre: doc.get("hooks", {}).pop("PreToolUse", None)
if "hooks" in doc and not doc["hooks"]: doc.pop("hooks")
path.write_text(json.dumps(doc, indent=2) + "\n")
PYEOF2
  fi
  rm -f "$STATE"
  ok "kept: .security-audit.conf, .security-exclusions.md, docs/security/scan-findings/, $KIT_REL/ (remove the kit dir yourself)"
}
if [ "$UNINSTALL" = 1 ]; then uninstall; exit 0; fi

echo "== prerequisite check (a missing one only skips that dimension; install still runs) =="
have docker && ok "docker (gitleaks/trivy/syft)" || miss "docker MISSING -> secret/container/sbom skipped"
{ have uvx || have pipx; } && ok "uvx/pipx (semgrep/checkov/pip-audit)" || miss "uvx/pipx MISSING -> sast/iac/py-deps skipped"
{ have pnpm || have yarn || have npm; } && ok "js package manager (js-deps)" || miss "js package manager MISSING -> js-deps skipped"

echo "== hooks =="
chmod +x "$KIT/scan.sh" "$KIT/hooks/pre-commit" "$KIT/hooks/pre-push"
# Hooks git feeds on stdin (the others inherit the terminal: reading it would hang a commit).
STDIN_HOOKS=" pre-push post-rewrite reference-transaction push-to-checkout "
# chain_wrapper <name> <user hooks dir as recorded> -> one wrapper in CHAIN_DIR
# shellcheck disable=SC2016  # it WRITES a script: its $vars expand when the wrapper runs
chain_wrapper(){
  local name="$1" udir="$2" w="$CHAIN_DIR/$1" stdin=0
  case "$STDIN_HOOKS" in *" $name "*) stdin=1 ;; esac
  {
    printf '#!/bin/sh\n# Generated by security-audit-kit install.sh (F10): the kit'"'"'s %s, then this repo'"'"'s own.\n' "$name"
    printf '# Undo: bash %s/install.sh --uninstall\n' "$KIT_REL"
    printf 'top="$(git rev-parse --show-toplevel)"\n'
    if [ -z "$udir" ]; then printf 'udir="$(git rev-parse --git-common-dir)/hooks"\n'
    else printf 'udir=%s; case "$udir" in /*) ;; *) udir="$top/$udir" ;; esac\n' "'$udir'"; fi
    printf 'kit="$top/%s/%s"; own="$udir/%s"\n' "$KIT_HOOKS" "$name" "$name"
    if [ "$stdin" = 1 ]; then
      printf 'in="$(mktemp)"; trap '"'"'rm -f "$in"'"'"' EXIT; cat > "$in"\n'
      printf '[ -x "$kit" ] && { "$kit" "$@" < "$in" || exit $?; }\n[ -x "$own" ] && { "$own" "$@" < "$in" || exit $?; }\nexit 0\n'
    else
      printf '[ -x "$kit" ] && { "$kit" "$@" || exit $?; }\n[ -x "$own" ] && { "$own" "$@" || exit $?; }\nexit 0\n'
    fi
  } > "$w"
  chmod +x "$w"
}
if [ "$SKILLS_ONLY" = "1" ]; then
  miss "skipped (--skills-only) — drive triggers via the pre-commit framework (.pre-commit-hooks.yaml)"
else
  cur="$(git config --get core.hooksPath 2>/dev/null || true)"
  # What was there before the FIRST install is what --uninstall restores; a re-run keeps it.
  if [ -z "$(state_get prev_hooks_path)" ]; then
    case "$cur" in "$KIT_HOOKS"|"$CHAIN_DIR") state_set prev_hooks_path "-unset-" ;; *) state_set prev_hooks_path "${cur:--unset-}" ;; esac
  fi
  prev="$(state_get prev_hooks_path)"; [ "$prev" = "-unset-" ] && prev=""
  if [ -n "$prev" ]; then udir_abs="$prev"; case "$udir_abs" in /*) ;; *) udir_abs="$ROOT/$prev" ;; esac
  else udir_abs="$GITDIR/hooks"; fi
  own=""
  if [ -d "$udir_abs" ]; then
    for f in "$udir_abs"/*; do
      [ -f "$f" ] && [ -x "$f" ] || continue
      case "$f" in *.sample) continue ;; esac
      own="$own ${f##*/}"
    done
  fi
  own="${own# }"
  if [ -z "$own" ]; then
    rm -rf "$CHAIN_DIR"
    git config core.hooksPath "$KIT_HOOKS"
    ok "core.hooksPath -> $KIT_HOOKS (pre-commit=staged+deps, pre-push=all)"
  else
    # This repo already runs hooks: chain them instead of silencing them.
    rm -rf "$CHAIN_DIR"; mkdir -p "$CHAIN_DIR"
    names="$(printf '%s\n' pre-commit pre-push $own | sort -u | tr '\n' ' ')"
    for n in $names; do chain_wrapper "$n" "$prev"; done
    git config core.hooksPath "$CHAIN_DIR"
    ok "found this repo's own hooks in ${prev:-.git/hooks}: $own"
    ok "  -> they keep running, after the kit's (chained via .git/security-audit-hooks; core.hooksPath points there)"
    if [ -f "$ROOT/.pre-commit-config.yaml" ] || grep -qs 'pre-commit' "$udir_abs/pre-commit" 2>/dev/null && grep -qs 'File generated by pre-commit' "$udir_abs/pre-commit"; then
      ok "  pre-commit framework detected: its hook stays in the chain. Alternative: install.sh --skills-only"
      echo "      and add this kit to .pre-commit-config.yaml (.pre-commit-hooks.yaml: sec-staged / sec-deps / sec-all)"
    fi
  fi
fi

if [ "$SKILLS_ONLY" != "1" ] && have docker; then
  ok "tip: bash $KIT_REL/scan.sh warm — pulls the scanner images + the trivy DB now, so the first pre-push does not wait"
fi

echo "== project config =="
if [ -f "$ROOT/.security-audit.conf" ]; then
  ok ".security-audit.conf already exists (preserved)"
  # A re-run after an update: never rewrite the team's config, but say which settings the new
  # example has that it does not (F25) — a new knob nobody hears about is a knob nobody sets.
  conf_keys(){ grep -oE '\$\{[A-Z][A-Z0-9_]*:=|^#? *[A-Z][A-Z0-9_]*=' "$1" | grep -oE '[A-Z][A-Z0-9_]*' | sort -u; }
  new_keys="$(comm -23 <(conf_keys "$KIT/security-audit.conf.example") \
                       <(grep -oE '[A-Z][A-Z0-9_]+' "$ROOT/.security-audit.conf" | sort -u) | tr '\n' ' ')"
  [ -n "${new_keys// /}" ] \
    && miss "settings in security-audit.conf.example that are not in your .security-audit.conf: ${new_keys% } (all optional; see the example)"
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
mkdir -p "$ROOT/.claude/skills/sec-threat-model"
cp "$KIT/skills/sec-threat-model.skill.md" "$ROOT/.claude/skills/sec-threat-model/SKILL.md"
ok ".claude/skills/sec-threat-model/SKILL.md (STRIDE + data-flow threat modeling)"
mkdir -p "$ROOT/.claude/skills/sec-audit"
cp "$KIT/skills/sec-audit.skill.md" "$ROOT/.claude/skills/sec-audit/SKILL.md"
ok ".claude/skills/sec-audit/SKILL.md (one-command orchestrator: scan + triage + signal-gated deep)"
mkdir -p "$ROOT/docs/security/scan-findings" 2>/dev/null || true
for s in $SKILLS; do state_set "skill_$s" "$(fsum "$ROOT/.claude/skills/$s/SKILL.md")"; done

echo "== agent hook (pre-install package check) =="
if [ "$AGENT_HOOK" = "1" ]; then
  chmod +x "$KIT/hooks/pre-tool-install.sh"
  if have python3; then
    # `set -e` would abort the installer on a non-zero python exit, so branch on it directly.
    if SETTINGS="$ROOT/.claude/settings.json" HOOKCMD="$HOOK_CMD" python3 - <<'PYEOF'
import json, os, pathlib
path = pathlib.Path(os.environ["SETTINGS"])
cmd = os.environ["HOOKCMD"]
doc = {}
if path.exists():
    try:
        doc = json.loads(path.read_text() or "{}")
    except ValueError:
        raise SystemExit("settings.json is not valid JSON — refusing to rewrite it")
hooks = doc.setdefault("hooks", {}).setdefault("PreToolUse", [])
entry = {"type": "command", "command": cmd, "timeout": 120}
for matcher in hooks:
    if matcher.get("matcher") == "Bash":
        inner = matcher.setdefault("hooks", [])
        if any(h.get("command") == cmd for h in inner):
            raise SystemExit(0)          # already wired: idempotent, nothing to do
        inner.append(entry)
        break
else:
    hooks.append({"matcher": "Bash", "hooks": [entry]})
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(doc, indent=2) + "\n")
PYEOF
    then
      state_set agent_hook 1
      ok ".claude/settings.json -> PreToolUse(Bash) runs hooks/pre-tool-install.sh"
    else
      miss ".claude/settings.json NOT modified — add this hook by hand (see README)"
    fi
  else
    miss "python3 MISSING -> cannot edit .claude/settings.json; add the PreToolUse entry by hand"
  fi
else
  miss "not wired (opt-in). Enable with: bash $KIT_REL/install.sh --with-agent-hook"
  echo "      what it does: checks a package with guarddog BEFORE 'npm i'/'pip install' runs it"
fi

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
  threat model  : /sec-threat-model in Claude (STRIDE/data-flow; new subsystem / design review)
  one-command   : /sec-audit in Claude (orchestrator: scan + triage + signal-gated deep passes)
  skills visible: open THIS repo root in Claude Code (not a parent folder) and start a NEW
                  session — only <root>/.claude/skills is scanned; confirm with /skills
  share w/ team : git add .claude/skills tools/security-audit-kit .security-audit.conf \\
                  .security-exclusions.md   (uncommitted works for YOU; teammates need the commit)
  pre-commit fw : already use pre-commit? add this repo via .pre-commit-hooks.yaml instead of
                  the kit's hooks; run 'install.sh --skills-only' for the skills (no hooksPath)
  agent hook    : install.sh --with-agent-hook -> checks a package BEFORE the agent installs it
                  (ad-hoc: bash $KIT_REL/scan.sh pkgcheck npm <pkg>)
  emergency bypass: SKIP_SECURITY=1 git commit   |   git push --no-verify
  undo          : bash $KIT_REL/install.sh --uninstall  (restores hooksPath; keeps config + edited skills)

HARD boundary: produces internal evidence; does NOT replace an ASV scan + pentest.
EOF
