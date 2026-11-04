#!/usr/bin/env bash
# scripts/release.sh — cut RC / final release tags with a safety preflight.
#
# Release model (see RELEASING.md): consumers pin to release tags, never main HEAD.
# Every stable vX.Y.Z is gated behind a release candidate vX.Y.Z-rc.N (marked pre-release)
# that we dogfood in real projects first. The final tag is cut on the EXACT tested RC commit.
#
# Usage:
#   scripts/release.sh preflight            # run all safety checks, tag nothing
#   scripts/release.sh rc [X.Y.Z]           # cut next vX.Y.Z-rc.N (X.Y.Z inferred from CHANGELOG if omitted)
#   scripts/release.sh final X.Y.Z          # cut final vX.Y.Z on the last tested RC commit
# Options:
#   --yes         don't prompt before pushing tags
#   --skip-e2e    skip tests/e2e.sh in preflight (still runs scan.sh verify)
#   --no-gh       create git tags only; skip GitHub release creation
#   --stable      (preflight) apply the stable-release gate; `final` always does
#   --ci-unverified="<reason>"   promote even though CI could not be verified; the reason is
#                 required and goes into the tag message
#
# The CI gate (F07): for a STABLE release, anything short of "every required check's newest run is
# completed + success on this exact commit, and origin/main is that commit" stops the release —
# no gh, a failed API call, no check-runs, a pending/missing check, an unverifiable remote HEAD.
# An RC only warns on those: its gate is the dogfood that follows.
set -euo pipefail

KIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
cd "$KIT_DIR"

# Our CI jobs (ci.yml + self-audit.yml). A fork that drops one (say `plugin`) sets its own list.
GH="${RELEASE_GH:-gh}"   # the gh binary; tests point it at a missing path to simulate "no gh"
REQUIRED_CHECKS="${RELEASE_REQUIRED_CHECKS:-shellcheck pytest e2e plugin checksums self-audit}"
MAIN_BRANCH="main"

say(){  printf '\033[36m[release]\033[0m %s\n' "$*"; }
ok(){   printf '\033[32m[release] OK\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[release] WARN\033[0m %s\n' "$*" >&2; }
die(){  printf '\033[31m[release] FAIL\033[0m %s\n' "$*" >&2; exit 1; }
have(){ command -v "$1" >/dev/null 2>&1; }

YES=0; SKIP_E2E=0; NO_GH=0; STABLE=0; CI_UNVERIFIED=""; CI_UNVERIFIED_SET=0; ARGS=()
for a in "$@"; do
  case "$a" in
    --yes)      YES=1 ;;
    --skip-e2e) SKIP_E2E=1 ;;
    --no-gh)    NO_GH=1 ;;
    --stable)   STABLE=1 ;;
    --ci-unverified=*) CI_UNVERIFIED="${a#--ci-unverified=}"; CI_UNVERIFIED_SET=1 ;;
    -h|--help)  sed -n '2,18p' "$0"; exit 0 ;;
    -*)         die "unknown option: $a" ;;
    *)          ARGS+=("$a") ;;
  esac
done
CMD="${ARGS[0]:-}"
[ "$CI_UNVERIFIED_SET" = 1 ] && [ -z "$CI_UNVERIFIED" ] && die "--ci-unverified needs a reason: --ci-unverified=\"<why CI could not be verified>\""

valid_ver(){ printf '%s' "$1" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; }
changelog_top_version(){ grep -oE '^## \[[0-9]+\.[0-9]+\.[0-9]+\]' CHANGELOG.md | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+'; }
require_changelog_version(){
  local want="$1" top
  top="$(changelog_top_version || true)"
  [ "$top" = "$want" ] \
    || die "CHANGELOG top version is '${top:-none}', expected '$want' — replace [Unreleased] with [$want] before cutting a tag"
}

# The plugin's version pins plugin users to a release, so it must BE that release: a stale
# plugin.json would ship new skills under an old version (or never reach users at all).
require_plugin_version(){
  local f=".claude-plugin/plugin.json" v
  [ -f "$f" ] || return 0
  v="$(grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$f" | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"
  [ "$v" = "$1" ] || die "$f has version '${v:-none}', expected '$1' — bump it with the CHANGELOG"
}

# install.sh removes a skill copy only if it is provably the kit's, and a RELEASED template is one of
# the proofs: the templates being released must be on record, or upgrading users keep stale copies.
require_skill_sums(){
  local f n s
  for f in skills/*/SKILL.md; do
    [ -f "$f" ] || continue
    n="${f#skills/}"; n="${n%/SKILL.md}"; s="$(cksum < "$f" | awk '{print $1"-"$2}')"
    grep -qx "$n $s" lib/released-skills.sums 2>/dev/null \
      || die "lib/released-skills.sums lacks the current $n template — run scripts/skill-sums.sh and commit"
  done
}

# Every release says what a consumer must do on upgrade, even if that is nothing (F25):
# bootstrap.sh --check shows these sections to someone about to update. "- None." is a valid body;
# a missing section is not, because then nobody decided.
require_upgrade_notes(){
  release_notes "$1" | grep -q '^### Upgrade notes' \
    || die "no '### Upgrade notes' in [$1] — add one (write '- None.' if nothing changes for consumers) before cutting a tag"
}

# CHANGELOG section body for a version (between "## [X.Y.Z]" and the next "## [").
release_notes(){
  awk -v hdr="## [$1]" '
    index($0,hdr)==1 {p=1; next}
    p && /^## \[/ {exit}
    p {print}
  ' CHANGELOG.md
}

confirm(){
  [ "$YES" = 1 ] && return 0
  printf '\033[33m%s [y/N]\033[0m ' "$1"
  read -r ans || ans=""
  case "$ans" in y|Y|yes|YES) return 0 ;; *) die "aborted" ;; esac
}

# Something the gate could not verify: stops a stable release (unless --ci-unverified gave a
# reason), warns on an RC.
unverified(){
  if [ "$STABLE" = 1 ]; then
    [ -n "$CI_UNVERIFIED" ] || die "$1 — a stable release needs verified CI (or --ci-unverified=\"<reason>\")"
    warn "$1 — proceeding: --ci-unverified \"$CI_UNVERIFIED\""
  else
    warn "$1 — verify before promoting"
  fi
}

check_ci(){
  local sha="$1" runs req row status concl
  if ! have "$GH"; then unverified "gh not installed — cannot verify CI for ${sha:0:12}"; return 0; fi
  say "checking CI status for ${sha:0:12} …"
  # One row per run: name, status, conclusion, id. A check re-run after a failure has several rows;
  # the NEWEST (highest id) decides, whatever order the API lists them in.
  if ! runs="$("$GH" api "repos/{owner}/{repo}/commits/$sha/check-runs" --paginate \
                 --jq '.check_runs[] | [.name, .status, (.conclusion // ""), (.id|tostring)] | @tsv' 2>/dev/null)"; then
    unverified "GitHub API call for check-runs failed"; return 0
  fi
  [ -n "$runs" ] || { unverified "no check-runs found for ${sha:0:12} (CI not run or not finished)"; return 0; }
  local bad=0
  for req in $REQUIRED_CHECKS; do
    row="$(printf '%s\n' "$runs" | awk -F'\t' -v n="$req" '$1==n && $4+0>=m {m=$4+0; r=$0} END{print r}')"
    if [ -z "$row" ]; then unverified "required check '$req' not found on ${sha:0:12}"; bad=1; continue; fi
    status="$(cut -f2 <<<"$row")"; concl="$(cut -f3 <<<"$row")"
    if [ "$status" != completed ]; then unverified "required check '$req' is pending ($status)"; bad=1; continue; fi
    [ "$concl" = success ] || die "required check '$req' = '$concl' (not success) — fix CI before releasing"
  done
  [ "$bad" = 0 ] && ok "required CI checks green ($REQUIRED_CHECKS)"
  return 0
}

preflight(){
  git rev-parse --show-toplevel >/dev/null 2>&1 || die "not a git repo"
  [ -f scan.sh ] && [ -f CHANGELOG.md ] || die "run from the kit repo (scan.sh / CHANGELOG.md missing)"
  local br; br="$(git rev-parse --abbrev-ref HEAD)"
  [ "$br" = "$MAIN_BRANCH" ] || die "on branch '$br'; releases are cut from '$MAIN_BRANCH'"
  git diff --quiet && git diff --cached --quiet || die "working tree not clean — commit or stash first"
  say "fetching origin/$MAIN_BRANCH …"
  local fetched=1
  git fetch -q origin "$MAIN_BRANCH" 2>/dev/null || fetched=0
  local head remote; head="$(git rev-parse HEAD)"; remote="$(git rev-parse "origin/$MAIN_BRANCH" 2>/dev/null || echo '')"
  if [ "$fetched" = 0 ] || [ -z "$remote" ]; then
    unverified "cannot verify origin/$MAIN_BRANCH (no origin, or fetch failed)"
  fi
  [ -z "$remote" ] || [ "$head" = "$remote" ] || die "HEAD (${head:0:12}) != origin/$MAIN_BRANCH (${remote:0:12}) — push/pull first"
  ok "on $MAIN_BRANCH, clean, in sync"
  say "verifying integrity (scan.sh verify) …"
  bash scan.sh verify >/dev/null 2>&1 || die "scan.sh verify failed — CHECKSUMS stale or files tampered; run 'bash scan.sh checksums' and commit"
  ok "CHECKSUMS current"
  if [ "$SKIP_E2E" = 1 ]; then warn "skipping e2e (--skip-e2e)"; else
    say "running tests/e2e.sh (use --skip-e2e to skip) …"
    bash tests/e2e.sh >/dev/null 2>&1 || die "tests/e2e.sh failed"
    ok "e2e passed"
  fi
  check_ci "$head"
}

cmd_rc(){
  local ver="${ARGS[1]:-}"
  [ -n "$ver" ] || ver="$(changelog_top_version)"
  [ -n "$ver" ] || die "could not infer version from CHANGELOG; pass X.Y.Z"
  valid_ver "$ver" || die "invalid version '$ver' (want X.Y.Z)"
  git rev-parse -q --verify "refs/tags/v$ver" >/dev/null && die "final tag v$ver already exists"
  require_changelog_version "$ver"
  require_upgrade_notes "$ver"
  require_plugin_version "$ver"
  require_skill_sums
  preflight
  local n=1 t
  while git rev-parse -q --verify "refs/tags/v${ver}-rc.$n" >/dev/null; do n=$((n+1)); done
  t="v${ver}-rc.$n"
  say "will tag $t at $(git rev-parse --short HEAD) and push to origin"
  [ "$NO_GH" = 1 ] || say "and create a GitHub pre-release"
  confirm "Cut RC $t?"
  git tag -a "$t" -m "$t"
  git push origin "$t"
  ok "pushed tag $t"
  if [ "$NO_GH" = 0 ] && have "$GH"; then
    "$GH" release create "$t" --prerelease --title "$t" \
      --notes "Release candidate for v${ver}. Testing in real projects before promotion (see RELEASING.md)." \
      && ok "created pre-release $t" || warn "gh release create failed — tag is pushed, create the release manually"
  fi
  say "NEXT: dogfood $t in real project(s) per RELEASING.md, then:  scripts/release.sh final $ver"
}

cmd_final(){
  local ver="${ARGS[1]:-}"
  [ -n "$ver" ] || die "usage: scripts/release.sh final X.Y.Z"
  STABLE=1
  valid_ver "$ver" || die "invalid version '$ver' (want X.Y.Z)"
  git rev-parse -q --verify "refs/tags/v$ver" >/dev/null && die "tag v$ver already exists"
  require_changelog_version "$ver"
  require_plugin_version "$ver"
  require_skill_sums
  local last_rc; last_rc="$(git tag -l "v${ver}-rc.*" | sort -V | tail -1)"
  [ -n "$last_rc" ] || die "no RC for v$ver — cut & test one first:  scripts/release.sh rc $ver"
  preflight
  local head rc_sha; head="$(git rev-parse HEAD)"; rc_sha="$(git rev-parse "${last_rc}^{commit}")"
  [ "$head" = "$rc_sha" ] || die "HEAD (${head:0:12}) != $last_rc (${rc_sha:0:12}) — promote the TESTED commit (git checkout $rc_sha) or cut a new RC"
  say "will tag v$ver (final) at ${head:0:12} == $last_rc and push to origin"
  [ "$NO_GH" = 1 ] || say "and create the GitHub 'latest' release from the CHANGELOG"
  confirm "Promote v$ver (from tested $last_rc)?"
  if [ -n "$CI_UNVERIFIED" ]; then
    git tag -a "v$ver" -m "v$ver" -m "CI unverified at release: $CI_UNVERIFIED"
  else
    git tag -a "v$ver" -m "v$ver"
  fi
  git push origin "v$ver"
  ok "pushed tag v$ver"
  if [ "$NO_GH" = 0 ] && have "$GH"; then
    local notes; notes="$(release_notes "$ver")"
    [ -n "$notes" ] || notes="Release v$ver. See CHANGELOG.md."
    printf '%s\n' "$notes" | "$GH" release create "v$ver" --latest --title "v$ver" --notes-file - \
      && ok "created release v$ver (latest)" || warn "gh release create failed — tag is pushed, create the release manually"
  fi
  ok "v$ver released."
}

case "$CMD" in
  preflight) preflight; ok "preflight passed" ;;
  rc)        cmd_rc ;;
  final)     cmd_final ;;
  ""|help)   sed -n '2,18p' "$0" ;;
  *)         die "unknown command: '$CMD' (preflight|rc|final)" ;;
esac
