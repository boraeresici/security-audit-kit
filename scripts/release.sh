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
set -euo pipefail

KIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
cd "$KIT_DIR"

REQUIRED_CHECKS="shellcheck pytest e2e checksums self-audit"   # our CI jobs (ci.yml + self-audit.yml)
MAIN_BRANCH="main"

say(){  printf '\033[36m[release]\033[0m %s\n' "$*"; }
ok(){   printf '\033[32m[release] OK\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[release] WARN\033[0m %s\n' "$*" >&2; }
die(){  printf '\033[31m[release] FAIL\033[0m %s\n' "$*" >&2; exit 1; }
have(){ command -v "$1" >/dev/null 2>&1; }

YES=0; SKIP_E2E=0; NO_GH=0; ARGS=()
for a in "$@"; do
  case "$a" in
    --yes)      YES=1 ;;
    --skip-e2e) SKIP_E2E=1 ;;
    --no-gh)    NO_GH=1 ;;
    -h|--help)  sed -n '2,18p' "$0"; exit 0 ;;
    -*)         die "unknown option: $a" ;;
    *)          ARGS+=("$a") ;;
  esac
done
CMD="${ARGS[0]:-}"

valid_ver(){ printf '%s' "$1" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; }
changelog_top_version(){ grep -oE '^## \[[0-9]+\.[0-9]+\.[0-9]+\]' CHANGELOG.md | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+'; }

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

check_ci(){
  local sha="$1" runs req concl missing=0
  if ! have gh; then warn "gh not installed — cannot verify CI for ${sha:0:12}; ensure it is green"; return 0; fi
  say "checking CI status for ${sha:0:12} …"
  runs="$(gh api "repos/{owner}/{repo}/commits/$sha/check-runs" --paginate \
           --jq '.check_runs[] | [.name,.conclusion] | @tsv' 2>/dev/null || echo '')"
  [ -n "$runs" ] || { warn "no check-runs found for ${sha:0:12} (CI not finished?) — verify manually"; return 0; }
  for req in $REQUIRED_CHECKS; do
    concl="$(printf '%s\n' "$runs" | awk -F'\t' -v n="$req" '$1==n{c=$2} END{print c}')"
    if [ -z "$concl" ]; then warn "required check '$req' not found on ${sha:0:12}"; missing=1
    elif [ "$concl" != success ]; then die "required check '$req' = '$concl' (not success) — fix CI before releasing"; fi
  done
  [ "$missing" = 0 ] && ok "required CI checks green ($REQUIRED_CHECKS)" || warn "some required checks missing — verify before promoting"
}

preflight(){
  git rev-parse --show-toplevel >/dev/null 2>&1 || die "not a git repo"
  [ -f scan.sh ] && [ -f CHANGELOG.md ] || die "run from the kit repo (scan.sh / CHANGELOG.md missing)"
  local br; br="$(git rev-parse --abbrev-ref HEAD)"
  [ "$br" = "$MAIN_BRANCH" ] || die "on branch '$br'; releases are cut from '$MAIN_BRANCH'"
  git diff --quiet && git diff --cached --quiet || die "working tree not clean — commit or stash first"
  say "fetching origin/$MAIN_BRANCH …"
  git fetch -q origin "$MAIN_BRANCH" || warn "git fetch failed (offline?) — in-sync check may be stale"
  local head remote; head="$(git rev-parse HEAD)"; remote="$(git rev-parse "origin/$MAIN_BRANCH" 2>/dev/null || echo '')"
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
  if [ "$NO_GH" = 0 ] && have gh; then
    gh release create "$t" --prerelease --title "$t" \
      --notes "Release candidate for v${ver}. Testing in real projects before promotion (see RELEASING.md)." \
      && ok "created pre-release $t" || warn "gh release create failed — tag is pushed, create the release manually"
  fi
  say "NEXT: dogfood $t in real project(s) per RELEASING.md, then:  scripts/release.sh final $ver"
}

cmd_final(){
  local ver="${ARGS[1]:-}"
  [ -n "$ver" ] || die "usage: scripts/release.sh final X.Y.Z"
  valid_ver "$ver" || die "invalid version '$ver' (want X.Y.Z)"
  git rev-parse -q --verify "refs/tags/v$ver" >/dev/null && die "tag v$ver already exists"
  local last_rc; last_rc="$(git tag -l "v${ver}-rc.*" | sort -V | tail -1)"
  [ -n "$last_rc" ] || die "no RC for v$ver — cut & test one first:  scripts/release.sh rc $ver"
  preflight
  local head rc_sha; head="$(git rev-parse HEAD)"; rc_sha="$(git rev-parse "${last_rc}^{commit}")"
  [ "$head" = "$rc_sha" ] || die "HEAD (${head:0:12}) != $last_rc (${rc_sha:0:12}) — promote the TESTED commit (git checkout $rc_sha) or cut a new RC"
  say "will tag v$ver (final) at ${head:0:12} == $last_rc and push to origin"
  [ "$NO_GH" = 1 ] || say "and create the GitHub 'latest' release from the CHANGELOG"
  confirm "Promote v$ver (from tested $last_rc)?"
  git tag -a "v$ver" -m "v$ver"
  git push origin "v$ver"
  ok "pushed tag v$ver"
  if [ "$NO_GH" = 0 ] && have gh; then
    local notes; notes="$(release_notes "$ver")"
    [ -n "$notes" ] || notes="Release v$ver. See CHANGELOG.md."
    printf '%s\n' "$notes" | gh release create "v$ver" --latest --title "v$ver" --notes-file - \
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
