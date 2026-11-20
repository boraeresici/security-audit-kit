#!/usr/bin/env bash
# security-audit-kit — agent PostToolUse hook (F33b): one advisory semgrep pass on the file the
# agent just edited, so a risky pattern is seen while the agent is still in that file, not at push.
#
# Shipped by the Claude Code plugin (hooks/hooks.json, matcher Edit|Write). It runs the REPO's
# vendored, pinned scanner (tools/security-audit-kit/scan.sh edit), never a copy of its own: the
# plugin downloads nothing, and the pin stays the team's decision.
#
# Contract: it never blocks (always exit 0). What the agent should hear goes to its context as
# hookSpecificOutput.additionalContext: new findings, or that the file was NOT checked and why.
# A clean file adds nothing. Off: EDIT_CHECK=0 (env or .security-audit.conf).
set -uo pipefail

have(){ command -v "$1" >/dev/null 2>&1; }
have python3 || exit 0          # cannot read the payload, so there is nothing true to say
payload="$(cat)"

# file path, session id: tab-separated, from the PostToolUse payload
fields="$(printf '%s' "$payload" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
f = (d.get("tool_input") or {}).get("file_path") or ""
s = d.get("session_id") or "none"
print(f + "\t" + s)' 2>/dev/null)" || exit 0
file="${fields%%	*}"; sid="${fields#*	}"
case "$file" in "") exit 0 ;; esac
[ -f "$file" ] || exit 0
root="$(git -C "$(dirname -- "$file")" rev-parse --show-toplevel 2>/dev/null)" || exit 0   # not in a repo

emit(){ python3 -c 'import json, sys; print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": sys.stdin.read().rstrip()}}))'; }

# A note about the setup (no vendored kit, an old one): once per session, kept where scan.sh keeps its own.
once(){
  local common d s
  common="$(git -C "$root" rev-parse --git-common-dir 2>/dev/null)" || return 0
  case "$common" in /*) ;; *) common="$root/$common" ;; esac
  d="$common/security-audit-cache/edit-check"; mkdir -p "$d" 2>/dev/null || return 0
  s="$d/$(printf '%s' "$sid" | tr -cd 'A-Za-z0-9_-' | cut -c1-64)"
  grep -qxF "skip	$1" "$s" 2>/dev/null && return 1
  printf 'skip\t%s\n' "$1" >> "$s"
}

case "${EDIT_CHECK:-1}" in 0|off) exit 0 ;; esac
kit="$root/tools/security-audit-kit"
dir="$(cd -P -- "$(dirname -- "$file")" && pwd -P)"; rel="$dir/$(basename -- "$file")"
rel="${rel#"$(cd -P -- "$root" && pwd -P)"/}"     # /var vs /private/var: compare physical paths
if [ ! -f "$kit/scan.sh" ]; then
  once no-kit && printf 'security-audit-kit: %s was not checked: this repo has no vendored scanner (tools/security-audit-kit). The plugin never downloads one; adding it is the user'"'"'s decision (bash bootstrap.sh <tag>, see the kit README). (Said once per session.)\n' "$rel" | emit
  exit 0
fi
if ! grep -q '^scan_edit()' "$kit/scan.sh"; then
  once old-kit && printf 'security-audit-kit: %s was not checked: the vendored kit predates the edit check. Run tools/security-audit-kit/bootstrap.sh --check and tell the user; updating the pin is their decision. (Said once per session.)\n' "$rel" | emit
  exit 0
fi
out="$(cd "$root" && bash "$kit/scan.sh" edit "$file" --session "$sid" 2>/dev/null)"
[ -n "$out" ] && printf '%s\n' "$out" | emit
exit 0
