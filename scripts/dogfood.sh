#!/usr/bin/env bash
# scripts/dogfood.sh — try a release tag on real consumer repos + a fresh install, one table out.
#
# The RC dogfood (RELEASING.md step 4) as a script. It caught nothing by itself before; people did:
# v1.20.0's two dogfood bugs were an RC pin offered a downgrade by `--check`, and every fresh
# install crashing sast. Both are exactly what this checks, on every RC, the same way every time.
#
#   scripts/dogfood.sh v1.21.0-rc.1 ~/src/app-a ~/src/app-b     # consumer repos (cloned, untouched)
#   scripts/dogfood.sh v1.21.0-rc.1                              # fresh install only
# Options:
#   --no-fresh   skip the fresh-install scenario
#   --keep       keep the work dir (clones + logs) and print where it is
# Env: KIT_REPO (default: this checkout's origin), DOGFOOD_WORK (work dir; default: a temp dir).
#
# Each consumer repo is CLONED into the work dir (committed state only): the real repo, its
# working tree and its hooks are never touched. Per repo: pin before; `--check` with the vendored
# (old) bootstrap; upgrade with the vendored bootstrap if there is one (the path consumers take),
# else this kit's; `--expect` on the tag's commit; `verify`; what the install re-run says; `scan.sh
# all` read from summary.json; `--check` again with the new bootstrap.
# FAIL (exit 1): bootstrap or verify failed, no summary.json, any dimension "error", or `--check`
# after the upgrade offering a tag OLDER than the one installed. Reported, not failed: "skipped"
# dimensions (a missing tool on this machine) and findings (a real repo has some).
set -uo pipefail

KIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
say(){  printf '\033[36m[dogfood]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[dogfood] WARN\033[0m %s\n' "$*" >&2; }
die(){  printf '\033[31m[dogfood] FAIL\033[0m %s\n' "$*" >&2; exit 2; }
have(){ command -v "$1" >/dev/null 2>&1; }

FRESH=1; KEEP=0; TAG=""; REPOS=()
for a in "$@"; do
  case "$a" in
    --no-fresh) FRESH=0 ;;
    --keep)     KEEP=1 ;;
    -h|--help)  sed -n '2,23p' "$0"; exit 0 ;;
    -*)         die "unknown option: $a" ;;
    *)          if [ -z "$TAG" ]; then TAG="$a"; else REPOS+=("$a"); fi ;;
  esac
done
[ -n "$TAG" ] || die "usage: scripts/dogfood.sh <tag> [repo...] [--no-fresh] [--keep]"
have git || die "git is missing"
have python3 || die "python3 is needed to read summary.json"

KIT_REPO="${KIT_REPO:-$(git -C "$KIT_DIR" remote get-url origin 2>/dev/null || echo https://github.com/boraeresici/security-audit-kit.git)}"
export KIT_REPO
# The commit the tag points at (peeled: an annotated tag's own object is not what --expect wants).
SHA="$(git ls-remote "$KIT_REPO" "refs/tags/$TAG^{}" 2>/dev/null | awk '{print $1}')"
[ -n "$SHA" ] || SHA="$(git ls-remote "$KIT_REPO" "refs/tags/$TAG" 2>/dev/null | awk '{print $1}')"
[ -n "$SHA" ] || die "tag $TAG not found in $KIT_REPO"

WORK="${DOGFOOD_WORK:-$(mktemp -d)}"; mkdir -p "$WORK"
[ "$KEEP" = 1 ] || trap 'rm -rf "$WORK"' EXIT
say "tag $TAG @ ${SHA:0:12} from $KIT_REPO · work dir $WORK"

# Release order (bootstrap.sh's rule): an RC before its final, rc.10 after rc.2.
release_key(){
  local t="${1#v}" b n
  b="$(printf '%s' "$t" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' || true)"; [ -n "$b" ] || return 0
  if [ "$t" = "$b" ]; then printf '%s.1\n' "$b"
  else n="$(printf '%s' "${t#"$b"}" | grep -oE '[0-9]+' | head -1 || true)"; printf '%s.0.%s\n' "$b" "${n:-0}"; fi
}
older_than(){   # <a> <b>: a comes before b in release order
  local ka kb; ka="$(release_key "$1")"; kb="$(release_key "$2")"
  [ -n "$ka" ] && [ -n "$kb" ] && [ "$ka" != "$kb" ] && [ "$(printf '%s\n%s\n' "$ka" "$kb" | sort -V | head -1)" = "$ka" ]
}

ROWS=(); FAILED=0
# <name> <dir> : run the scenario in an already prepared git repo at <dir>; appends one row.
dogfood_one(){
  local name="$1" dir="$2" log="$WORK/$1" kit="$2/tools/security-audit-kit"
  local pin_before="(none)" before="-" boot after="-" verify="-" allrc="-" secs="-" errs="" skipped="" newset="" fails=""
  mkdir -p "$log"
  [ -f "$kit/.kit-version" ] && pin_before="$(awk '{print $1; exit}' "$kit/.kit-version")"
  if [ -f "$kit/bootstrap.sh" ]; then
    (cd "$dir" && bash "$kit/bootstrap.sh" --check) > "$log/check-before.log" 2>&1
    before="$(sed 's/\x1b\[[0-9;]*m//g' "$log/check-before.log" | sed -n 's/.*UPDATE AVAILABLE -> .* \([^ ]*\)$/update→\1/p; s/.*up to date.*/up to date/p' | head -1)"
    boot="$kit/bootstrap.sh"
  else
    boot="$KIT_DIR/bootstrap.sh"
  fi
  cp "$boot" "$log/bootstrap.sh"   # rsync --delete replaces the vendored copy mid-run
  if ! (cd "$dir" && bash "$log/bootstrap.sh" "$TAG" --expect="$SHA") > "$log/bootstrap.log" 2>&1; then
    fails="$fails bootstrap"
  fi
  newset="$(sed 's/\x1b\[[0-9;]*m//g' "$log/bootstrap.log" | sed -n 's/.*not in your .security-audit.conf: \(.*\) (all optional.*/\1/p')"
  if (cd "$dir" && bash "$kit/scan.sh" verify) > "$log/verify.log" 2>&1; then verify=ok; else verify=FAIL; fails="$fails verify"; fi
  (cd "$dir" && bash "$kit/scan.sh" all) > "$log/all.log" 2>&1; allrc=$?
  local sum="$dir/docs/security/scan-findings/summary.json"
  if [ -f "$sum" ]; then
    read -r secs errs skipped < <(python3 -I - "$sum" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
st = lambda s: ",".join(x["name"] for x in d.get("dimensions", []) if x.get("status") == s) or "-"
print(d.get("seconds", "-"), st("error"), st("skipped"))
PY
)
    [ "$errs" = "-" ] || fails="$fails error:$errs"
  else
    fails="$fails no-summary"
  fi
  if [ -f "$kit/bootstrap.sh" ]; then
    (cd "$dir" && bash "$kit/bootstrap.sh" --check) > "$log/check-after.log" 2>&1
    local offer; offer="$(sed 's/\x1b\[[0-9;]*m//g' "$log/check-after.log" | sed -n 's/.*UPDATE AVAILABLE -> .* \([^ ]*\)$/\1/p' | head -1)"
    if [ -z "$offer" ]; then after="up to date"
    elif older_than "$offer" "$TAG"; then after="DOWNGRADE→$offer"; fails="$fails check-downgrade"
    else after="update→$offer"; fi
  fi
  [ -n "$fails" ] && FAILED=1
  ROWS+=("$name|${fails:+FAIL:}${fails:-ok}|$pin_before|$before|$verify|$allrc|$secs|$errs|$skipped|$after|${newset:--}")
}

for r in "${REPOS[@]+"${REPOS[@]}"}"; do
  [ -d "$r/.git" ] || [ -f "$r/.git" ] || { warn "$r is not a git repo — skipped"; continue; }
  name="$(basename "$(cd "$r" && pwd)")"
  say "$name: cloning (committed state) …"
  git clone -q --no-hardlinks "$r" "$WORK/repo-$name" 2>/dev/null || { warn "$name: clone failed"; FAILED=1; continue; }
  dogfood_one "$name" "$WORK/repo-$name"
done

if [ "$FRESH" = 1 ]; then
  say "fresh install: a new repo, bootstrap $TAG, first scan …"
  F="$WORK/repo-fresh"; mkdir -p "$F/src"
  ( cd "$F" && git init -q && printf 'import os\nprint(os.getcwd())\n' > src/main.py \
      && git add -A && git -c user.email=dogfood@kit -c user.name=dogfood commit -qm init )
  dogfood_one "(fresh install)" "$F"
fi

printf '\n== dogfood %s (%s) ==\n' "$TAG" "${SHA:0:12}"
{
  printf 'repo|verdict|pin before|--check before|verify|all rc|seconds|error dims|skipped dims|--check after|new settings\n'
  printf '%s\n' "${ROWS[@]+"${ROWS[@]}"}"
} | column -t -s '|' 2>/dev/null || printf '%s\n' "${ROWS[@]+"${ROWS[@]}"}"
printf '\nlogs: %s%s\n' "$WORK" "$([ "$KEEP" = 1 ] || echo '  (removed on exit; --keep to keep)')"
printf 'all rc=1 with no error dims = real findings (expected in a real repo). "skipped" = a tool missing here.\n'
if [ "$FAILED" = 1 ]; then printf '\033[31m[dogfood] FAIL\033[0m — do not promote %s\n' "$TAG"; exit 1; fi
printf '\033[32m[dogfood] OK\033[0m — %s passed the scripted checks; still do the manual checklist (RELEASING.md)\n' "$TAG"
