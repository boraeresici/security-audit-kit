#!/usr/bin/env bash
# security-audit-kit — agent PreToolUse hook: check a package BEFORE it is installed.
#
# The gap this closes: `npm i <pkg>` / `pip install <pkg>` runs the package's install script
# immediately. The kit's git hooks only see the changed manifest at commit time — after the code
# has already executed. This hook sits on the agent's tool call, so the check happens while
# nothing has run yet.
#
# Wire it up (OPT-IN — it fires on every Bash tool call), in .claude/settings.json:
#   "hooks": { "PreToolUse": [ { "matcher": "Bash", "hooks": [
#       { "type": "command", "timeout": 120,
#         "command": "bash \"$CLAUDE_PROJECT_DIR/tools/security-audit-kit/hooks/pre-tool-install.sh\"" } ] } ] }
#   (or: bash tools/security-audit-kit/install.sh --with-agent-hook)
#
# Scope, stated plainly: this guards the AGENT's tool calls. A human typing `npm i` in a terminal
# is not covered — nothing in a hook can see that.
#
# Contract: exit 0 = allow, exit 2 = block (stderr is shown to the agent). Anything the kit
# cannot check — no network, no guarddog, a VCS/local install, an unreadable payload — is ALLOWED
# and said out loud. A gate that blocks what it failed to inspect gets uninstalled, and an
# uninstalled gate protects nothing.
set -uo pipefail

payload="$(cat)"

# Fast path first (the Spotify ads-agentic-tools pattern): most Bash calls are not installs, and
# they must not pay for a python start-up.
case "$payload" in
  *npm*|*yarn*|*bun*|*pip*|*poetry*|*uv*) ;;   # npm covers pnpm, pip covers pipx
  *) exit 0 ;;
esac

KIT_DIR="${SECURITY_AUDIT_KIT_DIR:-}"
if [ -z "$KIT_DIR" ]; then
  unset CDPATH
  KIT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
fi
[ -f "$KIT_DIR/scan.sh" ] || exit 0   # kit not where we thought: allow, do not pretend to check

out="$(printf '%s' "$payload" | bash "$KIT_DIR/scan.sh" pkgcheck --hook 2>&1)"
rc=$?

if [ "$rc" -eq 1 ]; then
  {
    echo "BLOCKED by security-audit-kit: guarddog flagged a package on this install line."
    echo "$out"
    echo
    echo "Do NOT retry the install. Report the finding to the user with the rule names above."
    echo "If it is a known false positive, the escape hatches are: PKGCHECK_REPORT_EXTRA=<rule>"
    echo "for that rule, or SKIP_SECURITY=1 for this call — both are decisions to record, not"
    echo "defaults to reach for."
  } >&2
  exit 2
fi

# Not a block: print what was checked so the transcript carries it, and get out of the way.
[ -n "$out" ] && printf '%s\n' "$out"
exit 0
